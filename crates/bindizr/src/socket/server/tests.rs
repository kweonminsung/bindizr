use std::os::unix::fs::MetadataExt;

use serde_json::json;

use super::*;

/// Verify that invalid command fields are rejected instead of silently defaulting.
#[test]
fn command_rejects_wrongly_typed_fields() {
    let ok: DaemonCommand = serde_json::from_value(json!({
        "command": "create_tsig_key",
        "data": { "name": "k", "algorithm": null, "secret": null, "role_name": "admin" },
    }))
    .unwrap();
    assert!(matches!(ok, DaemonCommand::CreateTsigKey(request) if request.role_name == "admin"));

    // Defaulting invalid input could generate an unwanted key or apply a preview.
    serde_json::from_value::<DaemonCommand>(json!({
        "command": "create_tsig_key",
        "data": { "name": "k", "secret": 123, "role_name": "admin" },
    }))
    .unwrap_err();
    for run in [json!("true"), json!(true), json!(1)] {
        serde_json::from_value::<DaemonCommand>(json!({
            "command": "rollback_zone",
            "data": { "name": "z", "serial": 7, "run": run },
        }))
        .unwrap_err();
    }
}

/// Verify that a command round trips between client and server, its
/// payload nested under the command name.
#[test]
fn command_round_trips_between_client_and_server() {
    use bindizr_service::types::UpdateZoneRequest;

    let sent = DaemonCommand::UpdateZone {
        zone_name: "example.com".to_string(),
        request: UpdateZoneRequest {
            name: Some("new.example.com".to_string()),
            default_ttl: Some(300),
            ..UpdateZoneRequest::default()
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
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("run").join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    prepare_socket_path(socket_path).await.unwrap();

    let parent = std::fs::metadata(Path::new(socket_path).parent().unwrap()).unwrap();
    assert!(parent.is_dir());
    assert_eq!(parent.mode() & 0o777, 0o700);
}

/// Verify that `prepare_socket_path` refuses a parent reached through a symlink.
#[tokio::test]
async fn prepare_socket_path_rejects_symlinked_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("real")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
    let socket_path = dir.path().join("link").join("bindizr.sock");

    let err = prepare_socket_path(socket_path.to_str().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(err, BindSocketPathError::NotADirectory { .. }),
        "{err}"
    );
}

/// Verify the socket's owner and the UID both ends read for peer authorization.
#[tokio::test]
async fn accepted_connection_returns_peer_uid() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    let listener = bind_socket(socket_path).await.unwrap();
    let metadata = std::fs::metadata(socket_path).unwrap();
    let own_uid = read_own_uid().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = UnixListener::bind(socket_path).expect("failed to bind test socket");
    drop(listener);

    prepare_socket_path(socket_path).await.unwrap();

    assert!(!Path::new(socket_path).exists());
}

/// Verify that `prepare_socket_path` rejects active socket.
#[tokio::test]
async fn prepare_socket_path_rejects_active_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = UnixListener::bind(socket_path).expect("failed to bind test socket");

    let err = prepare_socket_path(socket_path).await.unwrap_err();

    assert!(matches!(err, BindSocketPathError::AlreadyRunning));
    assert!(Path::new(socket_path).exists());
    drop(listener);
}

/// Verify that `prepare_socket_path` rejects non socket file.
#[tokio::test]
async fn prepare_socket_path_rejects_non_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    std::fs::write(socket_path, "not a socket").unwrap();

    let err = prepare_socket_path(socket_path).await.unwrap_err();

    assert!(matches!(err, BindSocketPathError::NotASocket { .. }));
    assert!(Path::new(socket_path).exists());
}

/// Shutdown waits for committed commands and closes clients still waiting for input.
#[tokio::test]
async fn shutdown_finishes_started_commands_and_closes_idle_clients() {
    use std::{sync::Arc, time::Duration};

    use bindizr_core::{
        config::Config,
        dns::message::{Keepalive, OptRcode, ParsedQuery},
        metrics::Metrics,
    };
    use bindizr_service::{Context, authorization::Caller, secondary};
    use tokio::{net::UdpSocket, sync::watch, time::timeout};

    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".into();
    config.dns.notify.batch_ms = 0;
    config.dns.notify.timeout_secs = 3;
    config.dns.notify.retries = 0;
    let tls = TlsCertificates::load(&config).unwrap();
    let db = bindizr_db::Db::connect(&config.database).await.unwrap();
    let cx = Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        watch::channel(0).0,
    ));
    let secondary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let secondary_request = serde_json::from_value(json!({
        "name": "ack-gate",
        "address": secondary_socket.local_addr().unwrap().to_string(),
    }))
    .unwrap();
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
    let request = serde_json::from_value(json!({
        "name": "example.com",
        "mname": "ns1.example.com",
        "rname": "admin@example.com",
    }))
    .unwrap();
    let command = serde_json::to_string(&DaemonCommand::CreateZone(request)).unwrap();
    client
        .write_all(format!("{command}\n").as_bytes())
        .await
        .unwrap();
    let mut notify = [0; 4096];
    let (len, peer) = timeout(
        Duration::from_secs(2),
        secondary_socket.recv_from(&mut notify),
    )
    .await
    .unwrap()
    .unwrap();
    timeout(Duration::from_secs(2), async {
        while Arc::strong_count(&socket_cx) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown.trigger();
    assert!(
        timeout(Duration::from_millis(50), &mut server)
            .await
            .is_err()
    );
    let response = ParsedQuery::parse(&notify[..len], Keepalive::None)
        .unwrap()
        .build_signed_error_response(OptRcode::NOERROR, None, None)
        .unwrap();
    secondary_socket.send_to(&response, peer).await.unwrap();
    let mut response = String::new();
    timeout(
        Duration::from_secs(2),
        BufReader::new(client).read_line(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["data"]["zone"]["name"], "example.com");
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0];
    assert_eq!(idle_client.read(&mut byte).await.unwrap(), 0);
}
