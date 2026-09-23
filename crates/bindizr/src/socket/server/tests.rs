use serde_json::json;

use super::*;

/// Verify that `parse_params` rejects wrongly typed fields.
#[test]
fn parse_params_rejects_wrongly_typed_fields() {
    use bindizr_service::types::CreateTsigKeyRequest;

    use crate::socket::types::RollbackZoneParams;

    // Absent/null optional fields deserialize as their defaults...
    let ok: CreateTsigKeyRequest =
        parse_params(&json!({ "name": "k", "algorithm": null, "secret": null })).unwrap();
    assert!(!ok.global);
    let ok: RollbackZoneParams = parse_params(&json!({ "name": "z", "serial": 7 })).unwrap();
    assert!(!ok.dry_run);

    // ...but a present field of the wrong type is rejected instead of being
    // silently dropped, which would generate a secret instead of importing
    // one, or apply a rollback the caller asked to preview (a wrongly typed
    // dry_run once defaulted to false).
    let err =
        parse_params::<CreateTsigKeyRequest>(&json!({ "name": "k", "secret": 123 })).unwrap_err();
    assert_eq!(err.code, bindizr_service::error::ErrorCode::InvalidInput);
    for dry_run in [json!("true"), json!(1)] {
        let err = parse_params::<RollbackZoneParams>(
            &json!({ "name": "z", "serial": 7, "dry_run": dry_run }),
        )
        .unwrap_err();
        assert_eq!(err.code, bindizr_service::error::ErrorCode::InvalidInput);
    }
}

/// Verify that command payloads round trip between client and server.
#[test]
fn command_payloads_round_trip_between_client_and_server() {
    use bindizr_service::types::UpdateZoneRequest;

    use crate::socket::types::UpdateZoneParams;

    // The CLI serializes these and the daemon parses them back, so a flattened
    // request body must survive the round trip alongside its target field.
    let sent = serde_json::to_value(UpdateZoneParams {
        zone_name: "example.com".to_string(),
        request: UpdateZoneRequest {
            name: Some("new.example.com".to_string()),
            default_ttl: Some(300),
            ..UpdateZoneRequest::default()
        },
    })
    .unwrap();
    let parsed: UpdateZoneParams = parse_params(&sent).unwrap();
    assert_eq!(parsed.zone_name, "example.com");
    assert_eq!(parsed.request.name.as_deref(), Some("new.example.com"));
    assert_eq!(parsed.request.default_ttl, Some(300));
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
