use bindizr_core::config::Config;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::dns::record::Rdata;
use bindizr_core::dns::{Serial, SoaInterval, Ttl};
use bindizr_core::metrics::Metrics;
use bindizr_core::model::activity_log::{ActivityLog, ActivityOperation, ActivityResult};
use bindizr_core::model::change::ChangeSource;
use bindizr_core::model::dnssec_record::{DnssecRecord, DnssecRecordId, DnssecRecordType};
use bindizr_core::model::record::{Record, RecordId, RecordType};
use bindizr_core::model::role::{Role, RoleId};
use bindizr_core::model::zone::{Zone, ZoneId};
use bindizr_core::model::zone_version::{VersionFilter, ZoneVersion, ZoneVersionId};
use bindizr_db::Db;
use chrono::Utc;
use serde_json::json;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::authorization::Caller;
use crate::error::ErrorCode;
use crate::types::{
    ActivityLogFilter, ApiTokenFilter, PageRequest, RecordFilter, TsigKeyFilter, ZoneFilter,
};
use crate::{Context, activity, record, role, secondary, token, tsig_key, zone};

/// Build real service state over a disposable in-memory database.
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

/// Verify that an omitted limit is unbounded, while explicitly requested pages stay within the cap.
#[test]
fn page_limit_accepts_absence_and_rejects_out_of_range() {
    for limit in [None, Some(1), Some(MAX_PAGE_LIMIT)] {
        validate_page_limit(limit).unwrap();
    }

    for limit in [Some(0), Some(MAX_PAGE_LIMIT + 1), Some(u32::MAX)] {
        assert_eq!(
            validate_page_limit(limit).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }
}

/// Verify that joined metadata pages preserve role filters, all-zone grants, key names, and counts.
#[tokio::test]
async fn management_metadata_pages_keep_names_filters_and_cardinalities() {
    let cx = context().await;
    let caller = Caller::socket();
    role::create(
        &cx,
        &caller,
        &serde_json::from_value(json!({"name": "metadata"})).unwrap(),
    )
    .await
    .unwrap();
    zone::create(&cx, &caller, &serde_json::from_value(json!({
        "name": "metadata.example", "mname": "ns.metadata.example", "rname": "admin@metadata.example"
    })).unwrap()).await.unwrap();
    for zone_name in [None, Some("metadata.example")] {
        role::grant::create(
            &cx,
            &caller,
            "metadata",
            &serde_json::from_value(json!({
                "zone_name": zone_name, "actions": ["record:read"]
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    }
    for name in ["a-credential", "b-credential"] {
        token::create(
            &cx,
            &caller,
            &serde_json::from_value(json!({"name": name, "role_name": "metadata"})).unwrap(),
        )
        .await
        .unwrap();
        tsig_key::create(
            &cx,
            &caller,
            &serde_json::from_value(json!({"name": name, "role_name": "metadata"})).unwrap(),
        )
        .await
        .unwrap();
    }
    secondary::create(
        &cx,
        &caller,
        &serde_json::from_value(json!({
            "name": "metadata-secondary", "address": "192.0.2.1", "notify_tsig_key_name": "a-credential"
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let tokens = token::list(
        &cx,
        &caller,
        &ApiTokenFilter {
            role_name: Some("metadata".to_string()),
            limit: Some(1),
            offset: Some(1),
        },
    )
    .await
    .unwrap();
    assert_eq!(tokens.pagination.total, 2);
    assert_eq!(tokens.items[0].name, "a-credential");
    assert_eq!(tokens.items[0].role_name, "metadata");
    let all_tokens = token::list(&cx, &caller, &ApiTokenFilter::default())
        .await
        .unwrap();
    assert_eq!(
        all_tokens
            .items
            .iter()
            .map(|token| token.name.as_str())
            .collect::<Vec<_>>(),
        ["b-credential", "a-credential"]
    );
    let keys = tsig_key::list(
        &cx,
        &caller,
        &TsigKeyFilter {
            role_name: Some("metadata".to_string()),
            limit: Some(1),
            offset: Some(1),
        },
    )
    .await
    .unwrap();
    assert_eq!(keys.pagination.total, 2);
    assert_eq!(keys.items[0].name, "b-credential");
    let grants = role::grant::list(
        &cx,
        &caller,
        "metadata",
        PageRequest {
            limit: Some(1),
            offset: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(grants.pagination.total, 2);
    assert_eq!(grants.items[0].zone_name, None);
    let grants = role::grant::list(
        &cx,
        &caller,
        "metadata",
        PageRequest {
            limit: Some(1),
            offset: Some(1),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        grants.items[0].zone_name.as_deref(),
        Some("metadata.example")
    );
    let secondaries = secondary::list(
        &cx,
        &caller,
        PageRequest {
            limit: Some(1),
            offset: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        secondaries.items[0].notify_tsig_key_name.as_deref(),
        Some("a-credential")
    );
    let role = role::get_by_name(&cx, &caller, "metadata").await.unwrap();
    assert_eq!(
        (role.grant_count, role.token_count, role.tsig_key_count),
        (2, 2, 2)
    );
    let page = token::list(
        &cx,
        &caller,
        &ApiTokenFilter {
            limit: Some(1),
            offset: Some(u64::MAX),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.pagination.offset, u64::MAX);
    assert_eq!(page.pagination.total, 2);
}

/// Verify that Record and management listings return every row when a socket caller omits the limit.
#[tokio::test]
async fn listings_preserve_unbounded_windows_across_records_and_management() {
    let cx = context().await;

    let caller = Caller::socket();

    let mut tx = cx.db().begin().await.unwrap();

    let mut first_zone = None;

    for index in 0..1001 {
        let zone = bindizr_db::zone::create_tx(
            &mut tx,
            Zone {
                id: ZoneId::UNWRITTEN,
                name: ZoneName::parse(&format!("page{index:04}.example")).unwrap(),
                mname: "ns1.example".to_string(),
                rname: "admin@example".to_string(),
                default_ttl: Ttl::from_secs(300),
                serial: Serial::from(1001),
                refresh: SoaInterval::from_secs(300),
                retry: SoaInterval::from_secs(60),
                expire: SoaInterval::from_secs(3_600_000),
                minimum_ttl: Ttl::from_secs(300),
                dnssec_policy_id: None,
                parent_ns_addrs: None,
                enabled: true,
                description: None,
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();

        if first_zone.is_none() {
            first_zone = Some(zone);
        }

        bindizr_db::role::create_tx(
            &mut tx,
            Role {
                id: RoleId::UNWRITTEN,
                name: format!("page{index:04}"),
                description: None,
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();
        bindizr_db::activity_log::create_tx(
            &mut tx,
            &ActivityLog {
                id: 0,
                operation: ActivityOperation::RoleCreate,
                result: ActivityResult::Changed,
                target: activity::named_target(&format!("page{index:04}")),
                detail: None,
                source: ChangeSource::Socket,
                actor: None,
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    }

    let zone = first_zone.unwrap();
    let records: Vec<_> = (0..1001)
        .map(|index| Record {
            id: RecordId::UNWRITTEN,
            name: OwnerName::from_row(&format!("host{index:04}")).unwrap(),
            record_type: RecordType::A,
            value: "192.0.2.1".to_string(),
            ttl: Ttl::from_secs(300),
            priority: None,
            created_at: Utc::now(),
            zone_id: zone.id,
        })
        .collect();

    bindizr_db::record::create_many_tx(&mut tx, &records)
        .await
        .unwrap();

    let derived: Vec<_> = (0..3)
        .map(|index| DnssecRecord {
            id: DnssecRecordId::UNWRITTEN,
            zone_id: zone.id,
            name: OwnerName::from_row(&format!("key{index}")).unwrap(),
            record_type: DnssecRecordType::Dnskey,
            covered_record_type: None,
            ttl: Ttl::from_secs(300),
            rdata: Rdata::new(vec![1, 0, 3, 13, 1, 2, 3]).unwrap(),
            expires_at: None,
            record_set_digest: None,
        })
        .collect();

    bindizr_db::dnssec_record::create_many_tx(&mut tx, &derived)
        .await
        .unwrap();

    for serial in 1..=1001 {
        bindizr_db::zone_version::upsert_tx(
            &mut tx,
            ZoneVersion {
                id: ZoneVersionId::UNWRITTEN,
                zone_id: zone.id,
                serial: Serial::from(serial),
                mname: zone.mname.clone(),
                rname: "admin.example".to_string(),
                default_ttl: zone.default_ttl,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum_ttl: zone.minimum_ttl,
                source: ChangeSource::Socket,
                actor: None,
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    }

    tx.commit().await.unwrap();

    for (limit, offset, expected) in [
        (None, None, 1001),
        (Some(1000), None, 1000),
        (None, Some(1000), 1),
        (Some(2), Some(1000), 1),
        (None, Some(1001), 0),
        (None, Some(u64::MAX), 0),
    ] {
        let zones = zone::list_by_filter(
            &cx,
            &caller,
            &ZoneFilter {
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let records = record::list_by_filter_with_zone(
            &cx,
            &caller,
            &RecordFilter {
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let logs = activity::list(
            &cx,
            &caller,
            &ActivityLogFilter {
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let versions =
            zone::list_versions(&cx, &caller, &zone.name, limit, offset, VersionFilter::All)
                .await
                .unwrap();
        let filtered_versions = zone::list_versions(
            &cx,
            &caller,
            &zone.name,
            limit,
            offset,
            VersionFilter::ExcludePastSignerOnly,
        )
        .await
        .unwrap();

        for (count, pagination) in [
            (zones.items.len(), zones.pagination),
            (records.items.len(), records.pagination),
            (logs.items.len(), logs.pagination),
            (versions.items.len(), versions.pagination),
            (filtered_versions.items.len(), filtered_versions.pagination),
        ] {
            assert_eq!(count, expected, "limit={limit:?}, offset={offset:?}");
            assert_eq!(pagination.total, 1001);
            assert_eq!(pagination.limit, limit.unwrap_or(1001));
            assert_eq!(pagination.offset, offset.unwrap_or(0));
        }
    }

    for (offset, expected) in [(None, 1002), (Some(1000), 2)] {
        let roles = role::list(
            &cx,
            &caller,
            PageRequest {
                limit: None,
                offset,
            },
        )
        .await
        .unwrap();

        assert_eq!(roles.items.len(), expected);
        assert_eq!(roles.pagination.total, 1002);
        assert_eq!(roles.pagination.limit, 1002);
        assert_eq!(roles.pagination.offset, offset.unwrap_or(0));
    }

    // The user plane precedes the derived plane, even when an unbounded page starts in either.
    for (limit, offset, users, derived) in [
        (None, None, 1001, 3),
        (None, Some(1000), 1, 3),
        (None, Some(1001), 0, 3),
        (Some(2), Some(1000), 1, 1),
        (Some(2), Some(1001), 0, 2),
        (None, Some(1004), 0, 0),
        (None, Some(u64::MAX), 0, 0),
    ] {
        let records = record::list_by_filter_with_zone(
            &cx,
            &caller,
            &RecordFilter {
                include_dnssec: Some(true),
                limit,
                offset,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            records
                .items
                .iter()
                .filter(|record| record.id.is_some())
                .count(),
            users
        );
        assert_eq!(
            records
                .items
                .iter()
                .filter(|record| record.id.is_none())
                .count(),
            derived
        );
        assert!(
            records.items[..users]
                .iter()
                .all(|record| record.id.is_some())
        );
        assert!(
            records.items[users..]
                .iter()
                .all(|record| record.id.is_none())
        );
        assert_eq!(records.pagination.total, 1004);
        assert_eq!(records.pagination.limit, limit.unwrap_or(1004));
        assert_eq!(records.pagination.offset, offset.unwrap_or(0));
    }
}

/// Verify that bad page sizes are rejected before an unrelated role lookup can mask the input error.
#[tokio::test]
async fn management_listings_reject_invalid_limits_before_role_queries() {
    let cx = context().await;

    let caller = Caller::socket();

    for limit in [0, 1001] {
        let token_error = token::list(
            &cx,
            &caller,
            &ApiTokenFilter {
                role_name: Some("missing".to_string()),
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        let tsig_key_error = tsig_key::list(
            &cx,
            &caller,
            &TsigKeyFilter {
                role_name: Some("missing".to_string()),
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        let grant_error = role::grant::list(
            &cx,
            &caller,
            "missing",
            PageRequest {
                limit: Some(limit),
                offset: None,
            },
        )
        .await
        .unwrap_err();

        for error in [token_error, tsig_key_error, grant_error] {
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }
}
