use std::slice;

use bindizr_core::config::Config;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::dns::{Serial, SoaInterval, Ttl};
use bindizr_core::metrics::Metrics;
use bindizr_core::model::record::{Record, RecordId, RecordType};
use bindizr_core::model::zone::{Zone, ZoneId};
use bindizr_db::Db;
use chrono::Utc;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::authorization::Caller;
use crate::error::ErrorCode;
use crate::external_dns::change_set::{ZoneChangeSet, ZoneOperations};
use crate::types::{
    ApplyExternalDnsChangesRequest, CreateRoleGrantRequest, CreateRoleRequest, CreateTokenRequest,
    CreateZoneRequest, ExternalDnsRecord, ExternalDnsRecordUpdate, RoleGrantResponse,
};
use crate::{record, role, token, zone};

/// Build isolated SQLite service state without listeners or workers.
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

/// Create a zone with no ordinary records for authorization and rollback checks.
async fn create_zone(cx: &Context, zone_name: &str) {
    zone::create(
        cx,
        &Caller::socket(),
        &CreateZoneRequest {
            name: zone_name.to_string(),
            mname: format!("ns.{zone_name}"),
            rname: format!("hostmaster@{zone_name}"),
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
}

/// Issue a credential in a role that starts without any grant.
async fn credential(cx: &Context) -> String {
    let caller = Caller::socket();
    role::create(
        cx,
        &caller,
        &CreateRoleRequest {
            name: "external-dns".to_string(),
            description: None,
        },
    )
    .await
    .unwrap();
    token::create(
        cx,
        &caller,
        &CreateTokenRequest {
            name: "external-dns".to_string(),
            description: None,
            expires_in_days: None,
            role_name: "external-dns".to_string(),
        },
    )
    .await
    .unwrap()
    .1
}

/// Grant the fixture role the supplied actions on a named zone.
async fn grant(cx: &Context, zone_name: &str, actions: &[&str]) -> RoleGrantResponse {
    role::grant::create(
        cx,
        &Caller::socket(),
        "external-dns",
        &CreateRoleGrantRequest {
            zone_name: Some(zone_name.to_string()),
            actions: actions.iter().map(ToString::to_string).collect(),
            record_name_pattern: None,
            record_types: None,
        },
    )
    .await
    .unwrap()
}

/// Verify that zone visibility changes after request authentication are decided under the zone
/// lock.
#[tokio::test]
async fn apply_changes_uses_transactional_zone_visibility() {
    let cx = context().await;
    create_zone(&cx, "example.test").await;
    let secret = credential(&cx).await;
    let before_grant = Caller::authenticate_token(&cx, &secret).await.unwrap().0;
    let permission = grant(&cx, "example.test", &["record:create"]).await;
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set("app.example.test", "A", None, &["192.0.2.1"])],
        updates: Vec::new(),
        deletes: Vec::new(),
    };
    assert_eq!(
        apply_changes(&cx, &before_grant, &request)
            .await
            .unwrap()
            .added,
        1
    );

    let before_revoke = Caller::authenticate_token(&cx, &secret).await.unwrap().0;
    role::grant::revoke(&cx, &Caller::socket(), "external-dns", permission.id)
        .await
        .unwrap();
    let zone_name = ZoneName::parse("example.test").unwrap();
    let serial = zone::get_by_name(&cx, &Caller::socket(), &zone_name)
        .await
        .unwrap()
        .serial;

    // Even an idempotent request must not pass after its grant is gone.
    let error = apply_changes(&cx, &before_revoke, &request)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ZoneNotFound);
    assert_eq!(
        error.to_string(),
        "no zone is authoritative for 'app.example.test'"
    );
    assert_eq!(record::count_all(&cx).await.unwrap(), 1);
    assert_eq!(
        zone::get_by_name(&cx, &Caller::socket(), &zone_name)
            .await
            .unwrap()
            .serial,
        serial
    );
}

/// Verify that a hidden child shadows its granted parent and a later refusal rolls earlier zones
/// back.
#[tokio::test]
async fn apply_changes_rejects_hidden_subzones_and_rolls_back_all_zones() {
    let cx = context().await;
    create_zone(&cx, "a.example.test").await;
    create_zone(&cx, "example.test").await;
    create_zone(&cx, "internal.example.test").await;
    let secret = credential(&cx).await;
    grant(&cx, "a.example.test", &["record:create"]).await;
    grant(&cx, "example.test", &["record:create"]).await;
    let caller = Caller::authenticate_token(&cx, &secret).await.unwrap().0;
    let zone_name = ZoneName::parse("a.example.test").unwrap();
    let serial = zone::get_by_name(&cx, &Caller::socket(), &zone_name)
        .await
        .unwrap()
        .serial;
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![
            record_set("app.a.example.test", "A", None, &["192.0.2.1"]),
            record_set("app.internal.example.test", "A", None, &["192.0.2.2"]),
        ],
        updates: Vec::new(),
        deletes: Vec::new(),
    };

    let error = apply_changes(&cx, &caller, &request).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::ZoneNotFound);
    assert_eq!(
        error.to_string(),
        "no zone is authoritative for 'app.internal.example.test'"
    );
    assert_eq!(record::count_all(&cx).await.unwrap(), 0);
    assert_eq!(
        zone::get_by_name(&cx, &Caller::socket(), &zone_name)
            .await
            .unwrap()
            .serial,
        serial
    );
}

/// Build a zone fixture for the test.
fn test_zone(id: i32, zone_name: &str) -> Zone {
    Zone {
        id: ZoneId::from(id),
        name: ZoneName::parse(zone_name).unwrap(),
        mname: format!("ns1.{zone_name}"),
        rname: format!("hostmaster@{zone_name}"),
        default_ttl: Ttl::from_secs(3600),
        serial: Serial::from(1),
        refresh: SoaInterval::from_secs(7200),
        retry: SoaInterval::from_secs(3600),
        expire: SoaInterval::from_secs(604_800),
        minimum_ttl: Ttl::from_secs(86400),
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a record fixture with the requested fields.
fn test_record(id: i32, name: &str, record_type: RecordType, value: &str, ttl: i64) -> Record {
    Record {
        id: RecordId::from(id),
        name: OwnerName::from_row(name),
        record_type,
        value: value.to_string(),
        ttl: Ttl::try_from(ttl).unwrap(),
        priority: None,
        zone_id: ZoneId::from(1),
        created_at: Utc::now(),
    }
}

/// Build a record-group fixture from the supplied values.
fn record_set(
    name: &str,
    record_type: &str,
    ttl: Option<i64>,
    values: &[&str],
) -> ExternalDnsRecord {
    ExternalDnsRecord {
        name: name.to_string(),
        record_type: record_type.to_string(),
        ttl,
        values: values.iter().map(ToString::to_string).collect(),
    }
}

/// Verify that find authoritative zone picks most specific match.
#[test]
fn authoritative_zone_picks_most_specific_match() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];

    assert_eq!(
        policy::authoritative_zone(&zones, "api.internal.example.com").map(|(zone, _)| zone.id),
        Some(ZoneId::from(2))
    );
    assert_eq!(
        policy::authoritative_zone(&zones, "www.example.com").map(|(zone, _)| zone.id),
        Some(ZoneId::from(1))
    );
    assert_eq!(
        policy::authoritative_zone(&zones, "internal.example.com").map(|(zone, _)| zone.id),
        Some(ZoneId::from(2))
    );
}

/// Verify that `authoritative_zone` requires label boundary.
#[test]
fn authoritative_zone_requires_label_boundary() {
    let zones = vec![test_zone(1, "example.com")];

    assert!(policy::authoritative_zone(&zones, "notexample.com").is_none());
    assert!(policy::authoritative_zone(&zones, "example.org").is_none());
}

/// Verify that an escaped dot does not put a name inside the zone it spells.
#[test]
fn authoritative_zone_rejects_escaped_label_boundary() {
    // `evil\.example.com` is the two labels [evil.example, com], so no zone
    // named example.com is authoritative for it.
    let zones = vec![test_zone(1, "example.com")];
    let name = policy::normalize_lookup_name(r"evil\.example.com").unwrap();

    assert_eq!(name, r"evil\046example.com");
    assert!(policy::authoritative_zone(&zones, &name).is_none());
}

/// Verify that `normalize_lookup_name` lowercases and strips trailing dot.
#[test]
fn normalize_lookup_name_lowercases_and_strips_trailing_dot() {
    assert_eq!(
        policy::normalize_lookup_name("App.Example.COM.").unwrap(),
        "app.example.com"
    );
    assert!(policy::normalize_lookup_name("").is_err());
    assert!(policy::normalize_lookup_name("bad name.example.com").is_err());
}

/// Verify that `parse_record_set` rejects unsupported types.
#[test]
fn parse_record_set_rejects_unsupported_types() {
    for record_type in ["NS", "MX", "SRV", "SOA", "PTR"] {
        let error =
            change_set::parse_record_set(&record_set("a.example.com", record_type, None, &["x"]))
                .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }
    assert!(
        change_set::parse_record_set(&record_set("a.example.com", "BOGUS", None, &["x"])).is_err()
    );
}

/// Verify that `parse_record_set` rejects multi value CNAME and empty values.
#[test]
fn parse_record_set_rejects_multi_value_cname_and_empty_values() {
    let error = change_set::parse_record_set(&record_set(
        "a.example.com",
        "CNAME",
        None,
        &["one.example.com", "two.example.com"],
    ))
    .unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidRecordValue);

    let error =
        change_set::parse_record_set(&record_set("a.example.com", "A", None, &[])).unwrap_err();

    assert_eq!(error.code(), ErrorCode::InvalidInput);
}

/// Verify that `parse_record_set` normalizes TTL.
#[test]
fn parse_record_set_normalizes_ttl() {
    assert_eq!(
        change_set::parse_record_set(&record_set("a.example.com", "A", Some(0), &["192.0.2.1"]))
            .unwrap()
            .ttl,
        None
    );
    assert_eq!(
        change_set::parse_record_set(&record_set("a.example.com", "A", Some(300), &["192.0.2.1"]))
            .unwrap()
            .ttl,
        Some(Ttl::from_secs(300))
    );
    assert!(
        change_set::parse_record_set(&record_set("a.example.com", "A", Some(-1), &["192.0.2.1"]))
            .is_err()
    );
}

/// Verify that `parse_record_set` deduplicates equivalent ipv6 spellings.
#[test]
fn parse_record_set_deduplicates_equivalent_ipv6_spellings() {
    let parsed_record_set = change_set::parse_record_set(&record_set(
        "a.example.com",
        "AAAA",
        None,
        &["2001:DB8::1", "2001:db8:0:0:0:0:0:1"],
    ))
    .unwrap();

    assert_eq!(parsed_record_set.values, vec!["2001:db8::1".to_string()]);
}

/// Verify that `parse_record_set` parses quoted TXT values.
#[test]
fn parse_record_set_parses_quoted_txt_values() {
    let parsed_record_set = change_set::parse_record_set(&record_set(
        "a.example.com",
        "TXT",
        None,
        &["\"heritage=external-dns,external-dns/owner=default\""],
    ))
    .unwrap();

    assert_eq!(parsed_record_set.record_type, RecordType::Txt);
    assert_eq!(
        parsed_record_set.values[0],
        "\"heritage=external-dns,external-dns/owner=default\""
    );
    assert!(
        change_set::parse_record_set(&record_set(
            "a.example.com",
            "TXT",
            None,
            &["\"unterminated"]
        ))
        .is_err()
    );
}

/// Verify that `adjust_record_set` canonicalizes type and values.
#[test]
fn adjust_record_set_canonicalizes_type_and_values() {
    let adjusted = change_set::adjust_record_set(&record_set(
        "v6.example.com",
        "aaaa",
        None,
        &["2001:0DB8::2", "2001:db8::1", "2001:db8:0:0:0:0:0:1"],
    ))
    .unwrap();

    assert_eq!(adjusted.record_type, "AAAA");
    assert_eq!(adjusted.values, vec!["2001:db8::1", "2001:db8::2"]);

    let adjusted = change_set::adjust_record_set(&record_set(
        "c.example.com",
        "CNAME",
        Some(300),
        &["CDN.Example.NET"],
    ))
    .unwrap();

    assert_eq!(adjusted.values, vec!["cdn.example.net."]);
    assert_eq!(adjusted.ttl, Some(300));
}

/// Verify that `adjust_record_set` returns TXT values in presentation form.
#[test]
fn adjust_record_set_returns_txt_values_in_presentation_form() {
    let adjusted = change_set::adjust_record_set(&record_set(
        "t.example.com",
        "TXT",
        Some(0),
        &["v=spf1 -all"],
    ))
    .unwrap();

    assert_eq!(adjusted.values, vec!["\"v=spf1 -all\""]);

    // ExternalDNS sends TTL 0 for "not configured".
    assert_eq!(adjusted.ttl, None);

    // Already-canonical ownership records pass through byte-identical.
    let canonical = "\"heritage=external-dns,external-dns/owner=default\"";
    let adjusted =
        change_set::adjust_record_set(&record_set("t.example.com", "TXT", None, &[canonical]))
            .unwrap();

    assert_eq!(adjusted.values, vec![canonical]);

    let adjusted =
        change_set::adjust_record_set(&record_set("t.example.com", "TXT", None, &["   "])).unwrap();

    assert_eq!(adjusted.values, vec![r#""   ""#]);
}

/// Verify that `adjust_record_set` passes unparseable values through.
#[test]
fn adjust_record_set_passes_unparseable_values_through() {
    let adjusted =
        change_set::adjust_record_set(&record_set("bad.example.com", "A", None, &["not-an-ip"]))
            .unwrap();
    assert_eq!(adjusted.values, vec!["not-an-ip"]);
}

/// Verify that `adjust_record_set` rejects unsupported shapes.
#[test]
fn adjust_record_set_rejects_unsupported_shapes() {
    assert!(
        change_set::adjust_record_set(&record_set("a.example.com", "MX", None, &["x"])).is_err()
    );
    assert!(
        change_set::adjust_record_set(&record_set("a.example.com", "A", Some(-1), &["192.0.2.1"]))
            .is_err()
    );
    assert!(change_set::adjust_record_set(&record_set("a.example.com", "A", None, &[])).is_err());
    assert!(
        change_set::adjust_record_set(&record_set("a.example.com", "CNAME", None, &["a.", "b."]))
            .is_err()
    );
}

/// Verify that group operations resolves subzone without parent fallback.
#[test]
fn group_operations_by_zone_resolves_subzone_without_parent_fallback() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set(
            "api.internal.example.com",
            "A",
            None,
            &["192.0.2.1"],
        )],
        updates: Vec::new(),
        deletes: Vec::new(),
    };
    let operations = change_set::parse_changes_request(&request).unwrap();

    let grouped = change_set::group_operations_by_zone(&zones, operations).unwrap();

    assert_eq!(grouped.len(), 1);
    assert_eq!(
        grouped[&ZoneName::parse("internal.example.com").unwrap()].request_name,
        "api.internal.example.com"
    );
    assert!(grouped.contains_key(&ZoneName::parse("internal.example.com").unwrap()));
    assert_eq!(
        grouped[&ZoneName::parse("internal.example.com").unwrap()].adds[0].name,
        OwnerName::from_row("api")
    );
}

/// Verify that group operations rejects names without authoritative zone.
#[test]
fn group_operations_by_zone_rejects_names_without_authoritative_zone() {
    let zones = vec![test_zone(1, "example.com")];
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set("app.other.org", "A", None, &["192.0.2.1"])],
        updates: Vec::new(),
        deletes: Vec::new(),
    };
    let operations = change_set::parse_changes_request(&request).unwrap();

    let error = change_set::group_operations_by_zone(&zones, operations).unwrap_err();

    assert_eq!(error.code(), ErrorCode::ZoneNotFound);
}

/// Resolve an external-dns change request into operations for the test zone.
fn zone_operations(request: &ApplyExternalDnsChangesRequest, zone: &Zone) -> ZoneOperations {
    let operations = change_set::parse_changes_request(request).unwrap();
    let grouped = change_set::group_operations_by_zone(slice::from_ref(zone), operations).unwrap();

    grouped.into_values().next().unwrap_or_default()
}

/// Verify that change set creates new records with zone default TTL.
#[test]
fn change_set_creates_new_records_with_zone_default_ttl() {
    let zone = test_zone(1, "example.com");
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set("app.example.com", "A", None, &["192.0.2.1"])],
        updates: Vec::new(),
        deletes: Vec::new(),
    };

    let change_set = ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &[]).unwrap();

    assert!(change_set.deletes.is_empty());
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].name, OwnerName::from_row("app"));
    assert_eq!(change_set.creates[0].ttl, zone.default_ttl);
}

/// Verify that repeated creates preserve existing records even when their TTL differs.
#[test]
fn change_set_skips_existing_values_regardless_of_ttl() {
    let zone = test_zone(1, "example.com");
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set("app.example.com", "A", None, &["192.0.2.1"])],
        updates: Vec::new(),
        deletes: Vec::new(),
    };

    // An omitted TTL resolves to 3600; retrying must also preserve a row with TTL 300.
    for ttl in [3600, 300] {
        let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", ttl)];
        let change_set =
            ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap();
        assert!(change_set.deletes.is_empty(), "TTL {ttl}");
        assert!(change_set.creates.is_empty(), "TTL {ttl}");
    }
}

/// Verify that an explicit TTL-only update replaces the stored row instead of cancelling itself
/// as unchanged.
#[test]
fn change_set_replaces_rows_when_an_update_moves_only_the_ttl() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 300)];
    let request = ApplyExternalDnsChangesRequest {
        creates: Vec::new(),
        updates: vec![ExternalDnsRecordUpdate {
            old: record_set("app.example.com", "A", Some(300), &["192.0.2.1"]),
            new: record_set("app.example.com", "A", Some(900), &["192.0.2.1"]),
        }],
        deletes: Vec::new(),
    };

    let change_set =
        ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap();

    assert_eq!(change_set.deletes.len(), 1);
    assert_eq!(change_set.deletes[0].id, RecordId::from(10));
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].ttl, Ttl::from_secs(900));
}

/// Verify that change set skips deletes of absent records.
#[test]
fn change_set_skips_deletes_of_absent_records() {
    let zone = test_zone(1, "example.com");
    let request = ApplyExternalDnsChangesRequest {
        creates: Vec::new(),
        updates: Vec::new(),
        deletes: vec![record_set("gone.example.com", "A", None, &["192.0.2.9"])],
    };

    let change_set = ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &[]).unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

/// Verify that change set cancels unchanged updates even with reordered targets.
#[test]
fn change_set_cancels_unchanged_updates_even_with_reordered_targets() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ApplyExternalDnsChangesRequest {
        creates: Vec::new(),
        updates: vec![ExternalDnsRecordUpdate {
            old: record_set("app.example.com", "A", None, &["192.0.2.1", "192.0.2.2"]),
            new: record_set("app.example.com", "A", None, &["192.0.2.2", "192.0.2.1"]),
        }],
        deletes: Vec::new(),
    };

    let change_set =
        ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

/// Verify that change set replaces rows when update changes targets.
#[test]
fn change_set_replaces_rows_when_update_changes_targets() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ApplyExternalDnsChangesRequest {
        creates: Vec::new(),
        updates: vec![ExternalDnsRecordUpdate {
            old: record_set("app.example.com", "A", None, &["192.0.2.1", "192.0.2.2"]),
            new: record_set("app.example.com", "A", None, &["192.0.2.1", "192.0.2.3"]),
        }],
        deletes: Vec::new(),
    };

    let change_set =
        ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap();

    assert_eq!(
        change_set
            .deletes
            .iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec![RecordId::from(11)]
    );
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].value, "192.0.2.3");
}

/// Verify that change set replaces whole record set when TTL changes.
#[test]
fn change_set_replaces_whole_record_set_when_ttl_changes() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ApplyExternalDnsChangesRequest {
        creates: Vec::new(),
        updates: vec![ExternalDnsRecordUpdate {
            old: record_set(
                "app.example.com",
                "A",
                Some(3600),
                &["192.0.2.1", "192.0.2.2"],
            ),
            new: record_set(
                "app.example.com",
                "A",
                Some(300),
                &["192.0.2.1", "192.0.2.2"],
            ),
        }],
        deletes: Vec::new(),
    };

    let change_set =
        ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap();

    assert_eq!(change_set.deletes.len(), 2);
    assert_eq!(change_set.creates.len(), 2);
    assert!(
        change_set
            .creates
            .iter()
            .all(|record| record.ttl == Ttl::from_secs(300))
    );
}

/// Verify that change set enforces CNAME exclusivity.
#[test]
fn change_set_enforces_cname_exclusivity() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set(
            "app.example.com",
            "CNAME",
            None,
            &["cdn.example.net"],
        )],
        updates: Vec::new(),
        deletes: Vec::new(),
    };

    let error =
        ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap_err();

    assert_eq!(error.code(), ErrorCode::RecordConflict);
}

/// Verify that change set allows CNAME when conflicting row is deleted in same request.
#[test]
fn change_set_allows_cname_when_conflicting_row_is_deleted_in_same_request() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ApplyExternalDnsChangesRequest {
        creates: vec![record_set(
            "app.example.com",
            "CNAME",
            None,
            &["cdn.example.net"],
        )],
        updates: Vec::new(),
        deletes: vec![record_set("app.example.com", "A", None, &["192.0.2.1"])],
    };

    let change_set =
        ZoneChangeSet::compute(&zone, &zone_operations(&request, &zone), &existing).unwrap();

    assert_eq!(change_set.deletes.len(), 1);
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].record_type, RecordType::Cname);
}
