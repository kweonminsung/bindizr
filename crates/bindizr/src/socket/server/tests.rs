use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use bindizr_core::config::Config;
use bindizr_core::dns::message::{Keepalive, OptRcode, ParsedQuery};
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use bindizr_service::authorization::Caller;
use bindizr_service::secondary;
use bindizr_service::types::{CreateSecondaryRequest, CreateZoneRequest, UpdateZoneRequest};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::{task, time};

use super::*;

/// Verify that invalid command fields are rejected instead of silently defaulting.
#[test]
fn command_rejects_wrongly_typed_fields() {
    let ok: DaemonCommand = serde_json::from_value(json!({
        "command": "create_tsig_key",
        "data": { "name": "k", "algorithm": null, "secret": null, "role_name": "admin" }
    }))
    .unwrap();

    assert!(matches!(ok, DaemonCommand::CreateTsigKey(request) if request.role_name == "admin"));

    // Defaulting invalid input could generate an unwanted key or apply a preview.
    serde_json::from_value::<DaemonCommand>(json!({
        "command": "create_tsig_key",
        "data": { "name": "k", "secret": 123, "role_name": "admin" }
    }))
    .unwrap_err();

    for run in [json!("true"), json!(true), json!(1)] {
        serde_json::from_value::<DaemonCommand>(json!({
            "command": "rollback_zone",
            "data": { "name": "z", "serial": 7, "run": run }
        }))
        .unwrap_err();
    }
}

/// Verify that a command round trips between client and server, its
/// payload nested under the command name.
#[test]
fn command_round_trips_between_client_and_server() {
    let sent = DaemonCommand::UpdateZone {
        zone_name: "example.com".to_string(),
        request: UpdateZoneRequest {
            name: Some("new.example.com".to_string()),
            default_ttl: Some(300),
            ..Default::default()
        },
    };
    let line = serde_json::to_string(&sent).unwrap();

    assert!(line.starts_with(r#"{"command":"update_zone","data":{"zone_name":"example.com","#));
    let parsed: DaemonCommand = serde_json::from_str(&line).unwrap();

    assert_eq!(parsed, sent);

    // A command without a payload carries no `data`.
    assert_eq!(
        serde_json::to_string(&DaemonCommand::Status).unwrap(),
        r#"{"command":"status"}"#
    );
}

/// Verify that `prepare_socket_path` creates the parent directory owner-only.
#[tokio::test]
async fn prepare_socket_path_creates_parent_directory() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("run").join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    prepare_socket_path(socket_path).await.unwrap();

    let parent = fs::metadata(Path::new(socket_path).parent().unwrap()).unwrap();

    assert!(parent.is_dir());
    assert_eq!(parent.mode() & 0o777, 0o700);
}

/// Verify that `prepare_socket_path` refuses a parent reached through a symlink.
#[tokio::test]
async fn prepare_socket_path_rejects_symlinked_parent_directory() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("real")).unwrap();
    std::os::unix::fs::symlink(directory.path().join("real"), directory.path().join("link"))
        .unwrap();
    let socket_path = directory.path().join("link").join("bindizr.sock");

    let error = prepare_socket_path(socket_path.to_str().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(error, BindSocketPathError::NotADirectory { .. }),
        "{error}"
    );
}

/// Verify that the socket's owner and the UID both ends read for peer authorization agree.
#[tokio::test]
async fn accepted_connection_returns_peer_uid() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    let listener = bind_socket(socket_path).await.unwrap();

    let metadata = fs::metadata(socket_path).unwrap();
    let own_uid = socket::read_own_uid().unwrap();

    assert_eq!(own_uid, metadata.uid());

    let (client, accepted) = tokio::join!(UnixStream::connect(socket_path), listener.accept());

    // macOS reports no credentials once the peer has hung up, so the client
    // stays open while the daemon side asks.
    let client = client.unwrap();
    let (stream, _) = accepted.unwrap();

    assert_eq!(stream.peer_cred().unwrap().uid(), own_uid);
    assert_eq!(client.peer_cred().unwrap().uid(), own_uid);
}

/// Verify that `prepare_socket_path` removes stale socket.
#[tokio::test]
async fn prepare_socket_path_removes_stale_socket() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = UnixListener::bind(socket_path).unwrap();
    drop(listener);

    prepare_socket_path(socket_path).await.unwrap();

    assert!(!Path::new(socket_path).exists());
}

/// Verify that `prepare_socket_path` rejects active socket.
#[tokio::test]
async fn prepare_socket_path_rejects_active_socket() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = UnixListener::bind(socket_path).unwrap();

    let error = prepare_socket_path(socket_path).await.unwrap_err();

    assert!(matches!(error, BindSocketPathError::AlreadyRunning));
    assert!(Path::new(socket_path).exists());
    drop(listener);
}

/// Verify that `prepare_socket_path` rejects non socket file.
#[tokio::test]
async fn prepare_socket_path_rejects_non_socket_file() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    fs::write(socket_path, "not a socket").unwrap();

    let error = prepare_socket_path(socket_path).await.unwrap_err();

    assert!(matches!(error, BindSocketPathError::NotASocket { .. }));
    assert!(Path::new(socket_path).exists());
}

/// Verify that shutdown waits for committed commands and closes clients still waiting for input.
#[tokio::test]
async fn shutdown_finishes_started_commands_and_closes_idle_clients() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    config.dns.notify.batch_ms = 0;
    config.dns.notify.timeout_secs = 3;
    config.dns.notify.retries = 0;
    let tls = TlsCertificates::load(&config).unwrap();

    let db = Db::connect(&config.database).await.unwrap();
    let cx = Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        watch::channel(0).0,
    ));

    let secondary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let secondary_request = CreateSecondaryRequest {
        name: "ack-gate".to_string(),
        address: secondary_socket.local_addr().unwrap().to_string(),
        notify_key_name: None,
    };

    secondary::create(&cx, &Caller::socket(), &secondary_request)
        .await
        .unwrap();

    let (control_tx, _control_rx) = control::channel();
    let socket_cx = Arc::new(SocketContext::new(cx, control_tx, tls));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("drain.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let shutdown = Shutdown::new();
    let mut server = serve(socket_cx.clone(), listener, &shutdown).unwrap();

    let mut client = UnixStream::connect(&path).await.unwrap();
    let mut idle_client = UnixStream::connect(&path).await.unwrap();

    let request = CreateZoneRequest {
        name: "example.com".to_string(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: None,
        serial: None,
        refresh: None,
        retry: None,
        expire: None,
        minimum_ttl: None,
        description: None,
        apex_ns: true,
        dry_run: false,
    };
    let command = serde_json::to_string(&DaemonCommand::CreateZone(request)).unwrap();

    client
        .write_all(format!("{command}\n").as_bytes())
        .await
        .unwrap();

    let mut buffer = [0; 4096];

    let (len, peer) = time::timeout(
        Duration::from_secs(2),
        secondary_socket.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    time::timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&socket_cx) < 4 {
            task::yield_now().await;
        }
    })
    .await
    .unwrap();

    shutdown.trigger();

    assert!(
        time::timeout(Duration::from_millis(50), &mut server)
            .await
            .is_err()
    );
    let response = ParsedQuery::parse(&buffer[..len], Keepalive::None)
        .unwrap()
        .build_signed_error_response(OptRcode::NOERROR, None, None)
        .unwrap();

    secondary_socket.send_to(&response, peer).await.unwrap();

    let mut response = String::new();

    time::timeout(
        Duration::from_secs(2),
        BufReader::new(client).read_line(&mut response),
    )
    .await
    .unwrap()
    .unwrap();

    let response: Value = serde_json::from_str(&response).unwrap();

    assert_eq!(response["data"]["zone"]["name"], "example.com");

    time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();

    let mut byte = [0];

    assert_eq!(idle_client.read(&mut byte).await.unwrap(), 0);
}
