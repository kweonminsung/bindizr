use bindizr_core::{config::Config, metrics::Metrics, model::role_grant::Action};
use serde_json::json;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::{
    Context,
    error::ErrorCode,
    role, token,
    types::{CreateRoleGrantRequest, CreateRoleRequest, CreateTokenRequest, RoleGrantResponse},
    zone,
};

/// Build isolated service state over SQLite without background workers.
async fn context() -> Context {
    let config: Config = serde_json::from_value(json!({
        "database": {"sqlite": {"file_path": "sqlite::memory:"}},
    }))
    .unwrap();
    let db = bindizr_db::Db::connect(&config.database).await.unwrap();
    let (jobs, _rx) = mpsc::unbounded_channel();
    let (period, _rx) = watch::channel(0);
    Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        jobs,
        period,
    )
}

/// Grant the fixture role the supplied actions on the fixture zone.
async fn grant(cx: &Context, actions: &[&str]) -> RoleGrantResponse {
    role::grant::create(
        cx,
        &Caller::socket(),
        "writer",
        &CreateRoleGrantRequest {
            zone_name: Some("example.test".into()),
            actions: actions.iter().map(ToString::to_string).collect(),
            record_name_pattern: None,
            record_types: None,
        },
    )
    .await
    .unwrap()
}

/// Create a managed zone and a credential with read, create and update access.
async fn credential(cx: &Context) -> String {
    let admin = Caller::socket();
    zone::create(cx, &admin, &serde_json::from_value(json!({
        "name":"example.test", "mname":"ns.example.test", "rname":"hostmaster@example.test", "apex_ns":false,
    })).unwrap()).await.unwrap();
    role::create(
        cx,
        &admin,
        &CreateRoleRequest {
            name: "writer".into(),
            description: None,
        },
    )
    .await
    .unwrap();
    grant(cx, &["record:read", "record:create", "record:update"]).await;
    token::create(
        cx,
        &admin,
        &CreateTokenRequest {
            name: "writer-token".into(),
            description: None,
            expires_in_days: None,
            role_name: "writer".into(),
        },
    )
    .await
    .unwrap()
    .1
}

/// Every mutation and preview reports the grants reloaded under its zone lock.
#[tokio::test]
async fn record_write_actions_follow_transactional_grants() {
    for dry_run in [true, false] {
        for granted in [false, true] {
            let cx = context().await;
            let secret = credential(&cx).await;
            let admin = Caller::socket();
            let existing = create(
                &cx,
                &admin,
                &serde_json::from_value(json!({
                    "name":"existing", "type":"A", "value":"192.0.2.1", "zone_name":"example.test",
                }))
                .unwrap(),
            )
            .await
            .unwrap();
            let old_grant = if granted {
                None
            } else {
                Some(grant(&cx, &["record:delete"]).await)
            };
            let caller = Caller::authenticate_token(&cx, &secret).await.unwrap().0;

            if let Some(old_grant) = old_grant {
                role::grant::revoke(&cx, &admin, "writer", old_grant.id)
                    .await
                    .unwrap();
            } else {
                grant(&cx, &["record:delete"]).await;
            }

            let name = zone::normalize_name("example.test").unwrap();
            let before = zone::get_by_name(&cx, &admin, &name).await.unwrap();
            let count = count_all(&cx).await.unwrap();
            let created = create(&cx, &caller, &serde_json::from_value(json!({
                "name":"one", "type":"A", "value":"192.0.2.2", "zone_name":"example.test", "dry_run":dry_run,
            })).unwrap()).await.unwrap();
            let bulk = create_bulk(&cx, &caller, &serde_json::from_value(json!({
                "zone_name":"example.test", "records":[{"name":"two", "type":"A", "value":"192.0.2.3"}], "dry_run":dry_run,
            })).unwrap()).await.unwrap();
            let updated = update(
                &cx,
                &caller,
                existing.record.id.unwrap(),
                &serde_json::from_value(json!({
                    "value":"192.0.2.4", "dry_run":dry_run,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
            let updated_by_name = update_by_name(
                &cx,
                &caller,
                &name,
                "existing",
                &serde_json::from_value(json!({
                    "value":"192.0.2.5", "dry_run":dry_run,
                }))
                .unwrap(),
            )
            .await
            .unwrap();

            for record in [
                &created.record,
                &bulk.records[0],
                &updated.record,
                &updated_by_name.record,
            ] {
                assert_eq!(
                    record.actions.contains(&Action::RecordDelete),
                    granted,
                    "{record:?}"
                );
            }
            if dry_run {
                assert_eq!(count_all(&cx).await.unwrap(), count);
                assert_eq!(
                    zone::get_by_name(&cx, &admin, &name).await.unwrap().serial,
                    before.serial
                );
            } else {
                assert_eq!(count_all(&cx).await.unwrap(), count + 2);
            }
        }
    }
}

/// A credential revoked before the transaction cannot mutate or preview records.
#[tokio::test]
async fn record_writes_reject_revoked_credentials() {
    for dry_run in [true, false] {
        let cx = context().await;
        let secret = credential(&cx).await;
        let admin = Caller::socket();
        let existing = create(
            &cx,
            &admin,
            &serde_json::from_value(json!({
                "name":"existing", "type":"A", "value":"192.0.2.1", "zone_name":"example.test",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let caller = Caller::authenticate_token(&cx, &secret).await.unwrap().0;
        token::delete(&cx, &admin, "writer-token").await.unwrap();
        let name = zone::normalize_name("example.test").unwrap();
        let serial = zone::get_by_name(&cx, &admin, &name).await.unwrap().serial;
        let count = count_all(&cx).await.unwrap();

        let error = create(&cx, &caller, &serde_json::from_value(json!({
                "name":"one", "type":"A", "value":"192.0.2.2", "zone_name":"example.test", "dry_run":dry_run,
            })).unwrap()).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);

        let error = create_bulk(&cx, &caller, &serde_json::from_value(json!({
                "zone_name":"example.test", "records":[{"name":"two", "type":"A", "value":"192.0.2.3"}], "dry_run":dry_run,
            })).unwrap()).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);

        let error = update(
            &cx,
            &caller,
            existing.record.id.unwrap(),
            &serde_json::from_value(json!({
                "value":"192.0.2.4", "dry_run":dry_run,
            }))
            .unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);

        let error = update_by_name(
            &cx,
            &caller,
            &name,
            "existing",
            &serde_json::from_value(json!({
                "value":"192.0.2.5", "dry_run":dry_run,
            }))
            .unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);
        assert_eq!(count_all(&cx).await.unwrap(), count);
        assert_eq!(
            zone::get_by_name(&cx, &admin, &name).await.unwrap().serial,
            serial
        );
    }
}
