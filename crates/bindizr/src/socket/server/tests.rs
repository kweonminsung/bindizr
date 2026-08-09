use super::*;

/// Bind a test socket, or `None` in sandboxes that forbid Unix sockets.
fn try_bind_test_socket(socket_path: &str) -> Option<UnixListener> {
    match UnixListener::bind(socket_path) {
        Ok(listener) => Some(listener),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => None,
        Err(e) => panic!("failed to bind test socket: {}", e),
    }
}

#[test]
fn parse_params_rejects_wrongly_typed_fields() {
    use crate::api::types::CreateTsigKeyRequest;

    // Absent/null optional fields deserialize as their defaults...
    let ok: CreateTsigKeyRequest =
        parse_params(&json!({ "name": "k", "algorithm": null, "secret": null })).unwrap();
    assert!(!ok.global);

    // ...but a present field of the wrong type is rejected instead of being
    // silently dropped (which would e.g. generate a secret instead of
    // importing one).
    let err =
        parse_params::<CreateTsigKeyRequest>(&json!({ "name": "k", "secret": 123 })).unwrap_err();
    assert_eq!(err.code, bindizr_service::error::ErrorCode::InvalidInput);
}

#[test]
fn parse_params_rejects_a_wrongly_typed_rollback_dry_run() {
    use crate::api::types::RollbackZoneRequest;

    let ok: RollbackZoneRequest = parse_params(&json!({ "serial": 7 })).unwrap();
    assert!(!ok.dry_run);

    // A wrongly typed dry_run once defaulted to false, applying a rollback the
    // caller asked to preview.
    for dry_run in [json!("true"), json!(1)] {
        let err = parse_params::<RollbackZoneRequest>(&json!({ "serial": 7, "dry_run": dry_run }))
            .unwrap_err();
        assert_eq!(err.code, bindizr_service::error::ErrorCode::InvalidInput);
    }
}

#[test]
fn command_payloads_round_trip_between_client_and_server() {
    use crate::{
        api::types::{RollbackZoneRequest, UpdateZonePatch},
        socket::types::{RollbackZoneParams, UpdateZoneParams, ZoneNameParams},
    };

    // The CLI serializes these and the daemon parses them back, so a flattened
    // request body must survive the round trip alongside its target field.
    let sent = serde_json::to_value(UpdateZoneParams {
        name: "example.com".to_string(),
        patch: UpdateZonePatch {
            new_name: Some("new.example.com".to_string()),
            ttl: Some(300),
            ..UpdateZonePatch::default()
        },
    })
    .unwrap();
    let parsed: UpdateZoneParams = parse_params(&sent).unwrap();
    assert_eq!(parsed.name, "example.com");
    assert_eq!(parsed.patch.new_name.as_deref(), Some("new.example.com"));
    assert_eq!(parsed.patch.ttl, Some(300));

    let sent = serde_json::to_value(RollbackZoneParams {
        name: "example.com".to_string(),
        request: RollbackZoneRequest {
            serial: 7,
            dry_run: true,
        },
    })
    .unwrap();
    let parsed: RollbackZoneParams = parse_params(&sent).unwrap();
    assert_eq!(parsed.request.serial, 7);
    assert!(parsed.request.dry_run);

    let sent = serde_json::to_value(ZoneNameParams {
        name: "example.com".to_string(),
    })
    .unwrap();
    assert_eq!(
        parse_params::<ZoneNameParams>(&sent).unwrap().name,
        "example.com"
    );
}

#[tokio::test]
async fn prepare_socket_path_creates_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("run").join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    prepare_socket_path(socket_path).await.unwrap();

    assert!(Path::new(socket_path).parent().unwrap().exists());
}

#[tokio::test]
async fn prepare_socket_path_removes_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let Some(listener) = try_bind_test_socket(socket_path) else {
        return;
    };
    drop(listener);

    prepare_socket_path(socket_path).await.unwrap();

    assert!(!Path::new(socket_path).exists());
}

#[tokio::test]
async fn prepare_socket_path_rejects_active_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let Some(listener) = try_bind_test_socket(socket_path) else {
        return;
    };

    let err = prepare_socket_path(socket_path).await.unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert!(Path::new(socket_path).exists());
    drop(listener);
}

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
