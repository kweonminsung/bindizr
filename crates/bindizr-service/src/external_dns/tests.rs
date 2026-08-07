use chrono::Utc;

use super::{
    apply::{ZoneOps, compute_zone_change_set, convert_request, convert_rrset, group_ops_by_zone},
    policy::{find_authoritative_zone, normalize_lookup_name, stored_owner_name},
};
use crate::{
    error::ErrorCode,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    types::{ExternalDnsChangesRequest, ExternalDnsRrset, ExternalDnsRrsetUpdate},
};

fn test_zone(id: i32, name: &str) -> Zone {
    Zone {
        id,
        name: name.to_string(),
        primary_ns: format!("ns1.{}", name),
        admin_email: format!("hostmaster@{}", name),
        ttl: 3600,
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum_ttl: 86400,
        created_at: Utc::now(),
    }
}

fn test_record(id: i32, name: &str, record_type: RecordType, value: &str, ttl: i32) -> Record {
    Record {
        id,
        name: name.to_string(),
        record_type,
        value: value.to_string(),
        ttl,
        priority: None,
        zone_id: 1,
        created_at: Utc::now(),
    }
}

fn rrset(name: &str, record_type: &str, ttl: Option<i32>, values: &[&str]) -> ExternalDnsRrset {
    ExternalDnsRrset {
        name: name.to_string(),
        record_type: record_type.to_string(),
        ttl,
        values: values.iter().map(|v| v.to_string()).collect(),
    }
}

#[test]
fn find_authoritative_zone_picks_most_specific_match() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];

    assert_eq!(
        find_authoritative_zone(&zones, "api.internal.example.com").map(|z| z.id),
        Some(2)
    );
    assert_eq!(
        find_authoritative_zone(&zones, "www.example.com").map(|z| z.id),
        Some(1)
    );
    assert_eq!(
        find_authoritative_zone(&zones, "internal.example.com").map(|z| z.id),
        Some(2)
    );
}

#[test]
fn find_authoritative_zone_requires_label_boundary() {
    let zones = vec![test_zone(1, "example.com")];

    assert!(find_authoritative_zone(&zones, "notexample.com").is_none());
    assert!(find_authoritative_zone(&zones, "example.org").is_none());
}

#[test]
fn stored_owner_name_maps_apex_and_subnames() {
    let zone = test_zone(1, "example.com");

    assert_eq!(stored_owner_name("example.com", &zone), "@");
    assert_eq!(stored_owner_name("www.example.com", &zone), "www");
    assert_eq!(stored_owner_name("a.b.example.com", &zone), "a.b");
}

#[test]
fn normalize_lookup_name_lowercases_and_strips_trailing_dot() {
    assert_eq!(
        normalize_lookup_name("App.Example.COM.").unwrap(),
        "app.example.com"
    );
    assert!(normalize_lookup_name("").is_err());
    assert!(normalize_lookup_name("bad name.example.com").is_err());
}

#[test]
fn convert_rrset_rejects_unsupported_types() {
    for record_type in ["NS", "MX", "SRV", "SOA", "PTR"] {
        let err = convert_rrset(&rrset("a.example.com", record_type, None, &["x"])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
    assert!(convert_rrset(&rrset("a.example.com", "BOGUS", None, &["x"])).is_err());
}

#[test]
fn convert_rrset_rejects_multi_value_cname_and_empty_values() {
    let err = convert_rrset(&rrset(
        "a.example.com",
        "CNAME",
        None,
        &["one.example.com", "two.example.com"],
    ))
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRecordValue);

    let err = convert_rrset(&rrset("a.example.com", "A", None, &[])).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn convert_rrset_normalizes_ttl() {
    assert_eq!(
        convert_rrset(&rrset("a.example.com", "A", Some(0), &["192.0.2.1"]))
            .unwrap()
            .ttl,
        None
    );
    assert_eq!(
        convert_rrset(&rrset("a.example.com", "A", Some(300), &["192.0.2.1"]))
            .unwrap()
            .ttl,
        Some(300)
    );
    assert!(convert_rrset(&rrset("a.example.com", "A", Some(-1), &["192.0.2.1"])).is_err());
}

#[test]
fn convert_rrset_deduplicates_equivalent_ipv6_spellings() {
    let op = convert_rrset(&rrset(
        "a.example.com",
        "AAAA",
        None,
        &["2001:DB8::1", "2001:db8:0:0:0:0:0:1"],
    ))
    .unwrap();

    assert_eq!(op.values, vec!["2001:db8::1".to_string()]);
}

#[test]
fn convert_rrset_parses_quoted_txt_values() {
    let op = convert_rrset(&rrset(
        "a.example.com",
        "TXT",
        None,
        &["\"heritage=external-dns,external-dns/owner=default\""],
    ))
    .unwrap();

    assert_eq!(op.record_type, RecordType::TXT);
    assert!(op.values[0].starts_with("bindizr:txt-rdata:v1:"));
    assert!(convert_rrset(&rrset("a.example.com", "TXT", None, &["\"unterminated"])).is_err());
}

#[test]
fn group_ops_resolves_subzone_without_parent_fallback() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("api.internal.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };
    let ops = convert_request(&request).unwrap();

    let grouped = group_ops_by_zone(&zones, ops).unwrap();
    assert_eq!(grouped.len(), 1);
    assert!(grouped.contains_key("internal.example.com"));
    assert_eq!(grouped["internal.example.com"].adds[0].name, "api");
}

#[test]
fn group_ops_rejects_names_without_authoritative_zone() {
    let zones = vec![test_zone(1, "example.com")];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.other.org", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };
    let ops = convert_request(&request).unwrap();

    let err = group_ops_by_zone(&zones, ops).unwrap_err();
    assert_eq!(err.code, ErrorCode::ZoneNotFound);
}

fn zone_ops(request: &ExternalDnsChangesRequest, zone: &Zone) -> ZoneOps {
    let ops = convert_request(request).unwrap();
    let grouped = group_ops_by_zone(std::slice::from_ref(zone), ops).unwrap();
    grouped.into_values().next().unwrap_or_default()
}

#[test]
fn change_set_creates_new_records_with_zone_default_ttl() {
    let zone = test_zone(1, "example.com");
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };

    let change_set = compute_zone_change_set(&zone, &[], &zone_ops(&request, &zone)).unwrap();

    assert!(change_set.deletes.is_empty());
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].name, "app");
    assert_eq!(change_set.creates[0].ttl, zone.ttl);
}

#[test]
fn change_set_skips_creates_that_already_exist() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };

    let change_set = compute_zone_change_set(&zone, &existing, &zone_ops(&request, &zone)).unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

#[test]
fn change_set_skips_deletes_of_absent_records() {
    let zone = test_zone(1, "example.com");
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![],
        deletes: vec![rrset("gone.example.com", "A", None, &["192.0.2.9"])],
    };

    let change_set = compute_zone_change_set(&zone, &[], &zone_ops(&request, &zone)).unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

#[test]
fn change_set_cancels_unchanged_updates_even_with_reordered_targets() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRrsetUpdate {
            old: rrset("app.example.com", "A", None, &["192.0.2.1", "192.0.2.2"]),
            new: rrset("app.example.com", "A", None, &["192.0.2.2", "192.0.2.1"]),
        }],
        deletes: vec![],
    };

    let change_set = compute_zone_change_set(&zone, &existing, &zone_ops(&request, &zone)).unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

#[test]
fn change_set_replaces_rows_when_update_changes_targets() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRrsetUpdate {
            old: rrset("app.example.com", "A", None, &["192.0.2.1", "192.0.2.2"]),
            new: rrset("app.example.com", "A", None, &["192.0.2.1", "192.0.2.3"]),
        }],
        deletes: vec![],
    };

    let change_set = compute_zone_change_set(&zone, &existing, &zone_ops(&request, &zone)).unwrap();

    assert_eq!(
        change_set.deletes.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![11]
    );
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].value, "192.0.2.3");
}

#[test]
fn change_set_replaces_whole_rrset_when_ttl_changes() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRrsetUpdate {
            old: rrset("app.example.com", "A", Some(3600), &["192.0.2.1"]),
            new: rrset("app.example.com", "A", Some(300), &["192.0.2.1"]),
        }],
        deletes: vec![],
    };

    let change_set = compute_zone_change_set(&zone, &existing, &zone_ops(&request, &zone)).unwrap();

    assert_eq!(change_set.deletes.len(), 1);
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].ttl, 300);
}

#[test]
fn change_set_enforces_cname_exclusivity() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset(
            "app.example.com",
            "CNAME",
            None,
            &["cdn.example.net"],
        )],
        updates: vec![],
        deletes: vec![],
    };

    let err = compute_zone_change_set(&zone, &existing, &zone_ops(&request, &zone)).unwrap_err();
    assert_eq!(err.code, ErrorCode::RecordConflict);
}

#[test]
fn change_set_allows_cname_when_conflicting_row_is_deleted_in_same_request() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset(
            "app.example.com",
            "CNAME",
            None,
            &["cdn.example.net"],
        )],
        updates: vec![],
        deletes: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
    };

    let change_set = compute_zone_change_set(&zone, &existing, &zone_ops(&request, &zone)).unwrap();

    assert_eq!(change_set.deletes.len(), 1);
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].record_type, RecordType::CNAME);
}
