use serde_json::json;

use super::*;

/// Verify that a command payload of the wrong shape is refused as a whole,
/// instead of a wrongly typed field silently defaulting.
#[test]
fn command_rejects_wrongly_typed_fields() {
    // Absent optional fields deserialize as their defaults...
    let ok: DaemonCommand = serde_json::from_value(json!({
        "command": "create_tsig_key",
        "data": { "name": "k", "algorithm": null, "secret": null },
    }))
    .unwrap();
    assert!(matches!(ok, DaemonCommand::CreateTsigKey(request) if !request.global));

    // ...but a present field of the wrong type is rejected instead of being
    // dropped, which would generate a secret instead of importing one, or
    // apply a rollback the caller asked to preview.
    serde_json::from_value::<DaemonCommand>(json!({
        "command": "create_tsig_key",
        "data": { "name": "k", "secret": 123 },
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

/// Verify that `prepare_socket_path` creates parent directory.
#[tokio::test]
async fn prepare_socket_path_creates_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("run").join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    prepare_socket_path(socket_path).await.unwrap();

    assert!(Path::new(socket_path).parent().unwrap().exists());
}

/// Verify that a bound socket is owner-only and that an accepted connection
/// carries the peer's uid, which is what `serve` admits or refuses on.
#[tokio::test]
async fn accepted_connection_reports_the_peer_uid() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    let listener = bind_socket(socket_path).await.unwrap();
    let mode = std::fs::metadata(socket_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let (client, accepted) = tokio::join!(UnixStream::connect(socket_path), listener.accept());
    // macOS reports no credentials once the peer has hung up, so the client
    // stays open while the daemon side asks.
    let _client = client.unwrap();
    let (stream, _) = accepted.unwrap();
    assert_eq!(stream.peer_cred().unwrap().uid(), read_own_uid().unwrap());
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

    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
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

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert!(Path::new(socket_path).exists());
}
