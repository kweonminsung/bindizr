use bindizr_core::config::Config;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::metrics::Metrics;
use bindizr_core::model::role_grant::Action;
use bindizr_db::Db;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::error::ErrorCode;
use crate::types::{
    BulkRecordItem, CreateApiTokenRequest, CreateBulkRecordsRequest, CreateRecordRequest,
    CreateRoleGrantRequest, CreateRoleRequest, CreateZoneRequest, RoleGrantResponse,
    UpdateRecordRequest,
};
use crate::{Context, role, token, zone};

/// Build isolated service state over SQLite without background workers.
async fn context() -> Context {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    let db = Db::connect(&config.database).await.unwrap();
    Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        mpsc::channel(1).0,
        watch::channel(0).0,
    )
}

/// Grant the fixture role the supplied actions on the fixture zone.
async fn grant(cx: &Context, actions: &[&str]) -> RoleGrantResponse {
    role::grant::create(
        cx,
        &Caller::socket(),
        "writer",
        &CreateRoleGrantRequest {
            zone_name: Some("example.test".to_string()),
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
    zone::create(
        cx,
        &admin,
        &CreateZoneRequest {
            name: "example.test".to_string(),
            mname: "ns.example.test".to_string(),
            rname: "hostmaster@example.test".to_string(),
            default_ttl: None,
            serial: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum_ttl: None,
            description: None,
            apex_ns: false,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    role::create(
        cx,
        &admin,
        &CreateRoleRequest {
            name: "writer".to_string(),
            description: None,
        },
    )
    .await
    .unwrap();
    grant(cx, &["record:read", "record:create", "record:update"]).await;
    token::create(
        cx,
        &admin,
        &CreateApiTokenRequest {
            name: "writer-token".to_string(),
            description: None,
            expires_in_days: None,
            role_name: "writer".to_string(),
        },
    )
    .await
    .unwrap()
    .1
}

/// Verify that every mutation and preview reports the grants reloaded under its zone lock.
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
                &CreateRecordRequest {
                    name: "existing".to_string(),
                    record_type: "A".to_string(),
                    value: RecordValue::Text("192.0.2.1".to_string()),
                    ttl: None,
                    priority: None,
                    zone_name: "example.test".to_string(),
                    dry_run: false,
                },
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

            let zone_name = ZoneName::parse("example.test").unwrap();
            let before = zone::get_by_name(&cx, &admin, &zone_name).await.unwrap();
            let count = count_all(&cx).await.unwrap();
            let created = create(
                &cx,
                &caller,
                &CreateRecordRequest {
                    name: "one".to_string(),
                    record_type: "A".to_string(),
                    value: RecordValue::Text("192.0.2.2".to_string()),
                    ttl: None,
                    priority: None,
                    zone_name: "example.test".to_string(),
                    dry_run,
                },
            )
            .await
            .unwrap();
            let bulk = create_bulk(
                &cx,
                &caller,
                &CreateBulkRecordsRequest {
                    zone_name: "example.test".to_string(),
                    records: vec![BulkRecordItem {
                        name: "two".to_string(),
                        record_type: "A".to_string(),
                        value: RecordValue::Text("192.0.2.3".to_string()),
                        ttl: None,
                        priority: None,
                    }],
                    dry_run,
                },
            )
            .await
            .unwrap();
            let updated = update(
                &cx,
                &caller,
                existing.record.id.unwrap(),
                &UpdateRecordRequest {
                    value: Some(RecordValue::Text("192.0.2.4".to_string())),
                    dry_run,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let updated_by_name = update_by_name(
                &cx,
                &caller,
                &zone_name,
                "existing",
                &UpdateRecordRequest {
                    value: Some(RecordValue::Text("192.0.2.5".to_string())),
                    dry_run,
                    ..Default::default()
                },
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
                    zone::get_by_name(&cx, &admin, &zone_name)
                        .await
                        .unwrap()
                        .serial,
                    before.serial
                );
            } else {
                assert_eq!(count_all(&cx).await.unwrap(), count + 2);
            }
        }
    }
}

/// Verify that a credential revoked before the transaction cannot mutate or preview records.
#[tokio::test]
async fn record_writes_reject_revoked_credentials() {
    for dry_run in [true, false] {
        let cx = context().await;
        let secret = credential(&cx).await;
        let admin = Caller::socket();
        let existing = create(
            &cx,
            &admin,
            &CreateRecordRequest {
                name: "existing".to_string(),
                record_type: "A".to_string(),
                value: RecordValue::Text("192.0.2.1".to_string()),
                ttl: None,
                priority: None,
                zone_name: "example.test".to_string(),
                dry_run: false,
            },
        )
        .await
        .unwrap();
        let caller = Caller::authenticate_token(&cx, &secret).await.unwrap().0;
        token::delete(&cx, &admin, "writer-token").await.unwrap();
        let zone_name = ZoneName::parse("example.test").unwrap();
        let serial = zone::get_by_name(&cx, &admin, &zone_name)
            .await
            .unwrap()
            .serial;
        let count = count_all(&cx).await.unwrap();

        let error = create(
            &cx,
            &caller,
            &CreateRecordRequest {
                name: "one".to_string(),
                record_type: "A".to_string(),
                value: RecordValue::Text("192.0.2.2".to_string()),
                ttl: None,
                priority: None,
                zone_name: "example.test".to_string(),
                dry_run,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);

        let error = create_bulk(
            &cx,
            &caller,
            &CreateBulkRecordsRequest {
                zone_name: "example.test".to_string(),
                records: vec![BulkRecordItem {
                    name: "two".to_string(),
                    record_type: "A".to_string(),
                    value: RecordValue::Text("192.0.2.3".to_string()),
                    ttl: None,
                    priority: None,
                }],
                dry_run,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);

        let error = update(
            &cx,
            &caller,
            existing.record.id.unwrap(),
            &UpdateRecordRequest {
                value: Some(RecordValue::Text("192.0.2.4".to_string())),
                dry_run,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);

        let error = update_by_name(
            &cx,
            &caller,
            &zone_name,
            "existing",
            &UpdateRecordRequest {
                value: Some(RecordValue::Text("192.0.2.5".to_string())),
                dry_run,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidToken);
        assert_eq!(count_all(&cx).await.unwrap(), count);
        assert_eq!(
            zone::get_by_name(&cx, &admin, &zone_name)
                .await
                .unwrap()
                .serial,
            serial
        );
    }
}
