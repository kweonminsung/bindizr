use bindizr_core::{
    config::Config,
    dns::{
        Serial, SoaInterval, Ttl,
        name::{OwnerName, ZoneName},
        record::Rdata,
    },
    metrics::Metrics,
    model::{
        audit_log::{AuditEntity, AuditLog, AuditLogId, AuditOperation},
        dnssec_record::{DnssecRecord, DnssecRecordId, DnssecRecordType},
        record::{Record, RecordId, RecordType},
        role::{Role, RoleId},
        zone::Zone,
        zone_version::{ChangeSource, VersionFilter, ZoneVersion, ZoneVersionId},
    },
};
use bindizr_db::Db;
use chrono::Utc;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::{
    Context, audit,
    authorization::Caller,
    error::ErrorCode,
    record, role,
    types::{AuditLogFilter, PageRequest, RecordFilter, TokenFilter, TsigKeyFilter, ZoneFilter},
    zone,
};

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
        watch::channel(0).0,
    )
}

/// An omitted limit is unbounded, while explicitly requested pages stay within the cap.
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

/// Collection paging retains the unbounded request and reports offsets without truncating them.
#[test]
fn build_page_preserves_unbounded_windows_and_metadata() {
    for (limit, offset, expected) in [
        (None, None, 1001),
        (Some(1000), None, 1000),
        (None, Some(1000), 1),
        (Some(2), Some(1000), 1),
        (None, Some(1001), 0),
        (None, Some(u64::MAX), 0),
    ] {
        let page = build_page((0..1001).collect(), limit, offset);
        assert_eq!(page.items.len(), expected);
        assert_eq!(page.pagination.total, 1001);
        assert_eq!(page.pagination.limit, limit.unwrap_or(1001));
        assert_eq!(page.pagination.offset, offset.unwrap_or(0));
    }
}

/// SQL and collection listings must return every row when a socket caller omits the limit.
#[tokio::test]
async fn listings_preserve_unbounded_windows_across_sql_and_collections() {
    let cx = context().await;

    let caller = Caller::socket();

    let mut tx = cx.db().begin().await.unwrap();

    let mut first_zone = None;

    for index in 0..1001 {
        let zone = bindizr_db::zone::create_tx(
            &mut tx,
            Zone {
                id: crate::model::zone::ZoneId::UNWRITTEN,
                name: ZoneName::parse(&format!("page{index:04}.example")).unwrap(),
                mname: "ns1.example".into(),
                rname: "admin@example".into(),
                default_ttl: Ttl::from_secs(300),
                serial: Serial::from(1001),
                refresh: SoaInterval::from_secs(300),
                retry: SoaInterval::from_secs(60),
                expire: SoaInterval::from_secs(3600000),
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
        bindizr_db::audit_log::create_tx(
            &mut tx,
            AuditLog {
                id: AuditLogId::UNWRITTEN,
                entity: AuditEntity::Role,
                entity_name: format!("page{index:04}"),
                operation: AuditOperation::Create,
                detail: None,
                change_source: ChangeSource::Socket,
                changed_by: None,
                created_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    }

    let zone = first_zone.unwrap();
    let records = (0..1001)
        .map(|index| Record {
            id: RecordId::UNWRITTEN,
            name: OwnerName::from_row(&format!("host{index:04}")),
            record_type: RecordType::A,
            value: "192.0.2.1".into(),
            ttl: Ttl::from_secs(300),
            priority: None,
            created_at: Utc::now(),
            zone_id: zone.id,
        })
        .collect::<Vec<_>>();

    bindizr_db::record::create_many_tx(&mut tx, &records)
        .await
        .unwrap();

    let derived = (0..3)
        .map(|index| DnssecRecord {
            id: DnssecRecordId::UNWRITTEN,
            zone_id: zone.id,
            name: OwnerName::from_row(&format!("key{index}")),
            record_type: DnssecRecordType::Dnskey,
            covered_record_type: None,
            ttl: Ttl::from_secs(300),
            rdata: Rdata::new(vec![1, 0, 3, 13, 1, 2, 3]).unwrap(),
            expires_at: None,
            record_set_digest: None,
        })
        .collect::<Vec<_>>();

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
                rname: "admin.example".into(),
                default_ttl: zone.default_ttl,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum_ttl: zone.minimum_ttl,
                change_source: ChangeSource::Socket,
                changed_by: None,
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
            ZoneFilter {
                limit,
                offset,
                ..ZoneFilter::default()
            },
        )
        .await
        .unwrap();
        let records = record::list_by_filter_with_zone(
            &cx,
            &caller,
            RecordFilter {
                limit,
                offset,
                ..RecordFilter::default()
            },
        )
        .await
        .unwrap();
        let audits = audit::list(
            &cx,
            &caller,
            AuditLogFilter {
                limit,
                offset,
                ..AuditLogFilter::default()
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
            (audits.items.len(), audits.pagination),
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
            RecordFilter {
                signed: Some(true),
                limit,
                offset,
                ..RecordFilter::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            records.items.iter().filter(|row| row.id.is_some()).count(),
            users
        );
        assert_eq!(
            records.items.iter().filter(|row| row.id.is_none()).count(),
            derived
        );
        assert!(records.items[..users].iter().all(|row| row.id.is_some()));
        assert!(records.items[users..].iter().all(|row| row.id.is_none()));
        assert_eq!(records.pagination.total, 1004);
        assert_eq!(records.pagination.limit, limit.unwrap_or(1004));
        assert_eq!(records.pagination.offset, offset.unwrap_or(0));
    }
}

/// Bad page sizes are rejected before an unrelated role lookup can mask the input error.
#[tokio::test]
async fn collection_listings_reject_invalid_limits_before_role_queries() {
    let cx = context().await;

    let caller = Caller::socket();

    for limit in [0, 1001] {
        let token = crate::token::list(
            &cx,
            &caller,
            &TokenFilter {
                role_name: Some("missing".into()),
                limit: Some(limit),
                ..TokenFilter::default()
            },
        )
        .await
        .unwrap_err();
        let tsig = crate::tsig_key::list(
            &cx,
            &caller,
            &TsigKeyFilter {
                role_name: Some("missing".into()),
                limit: Some(limit),
                ..TsigKeyFilter::default()
            },
        )
        .await
        .unwrap_err();
        let grant = role::grant::list(
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

        for error in [token, tsig, grant] {
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }
}
