use bindizr_core::dns::name::ZoneName;
use chrono::Utc;

use super::*;
use crate::model::record::RecordType;

/// Build the test zone or its DNS name.
fn zone() -> Zone {
    Zone {
        id: 1,
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: 300,
        serial: 5,
        refresh: 300,
        retry: 60,
        expire: 3600000,
        minimum_ttl: 900,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build an existing database record for import planning.
fn existing(id: i32, name: &str, record_type: RecordType, value: &str, ttl: i32) -> Record {
    Record {
        id,
        name: OwnerName::parse_in_zone(name, &zone().name).unwrap(),
        record_type,
        value: value.to_string(),
        ttl,
        priority: None,
        created_at: Utc::now(),
        zone_id: 1,
    }
}

/// Build a desired imported record with an optional explicit TTL.
fn desired(name: &str, record_type: RecordType, value: &str, ttl: Option<i32>) -> DesiredRecord {
    DesiredRecord {
        stored_name: OwnerName::parse_in_zone(name, &zone().name).unwrap(),
        prepared: PreparedRecord {
            owner_name: name.to_string(),
            record_type,
            value: value.to_string(),
            ttl,
            priority: None,
        },
    }
}

/// Collect record IDs for import-plan assertions.
fn ids(records: &[Record]) -> Vec<i32> {
    records.iter().map(|r| r.id).collect()
}

/// Collect values added by an import plan.
fn added<'a>(plan: &ImportPlan<'a>) -> Vec<&'a str> {
    plan.adds
        .iter()
        .map(|a| a.prepared.value.as_str())
        .collect()
}

/// Verify that append never deletes what it did not ask about.
#[test]
fn append_never_deletes_what_it_did_not_ask_about() {
    let rows = [existing(1, "old", RecordType::A, "192.0.2.9", 300)];
    let want = [desired("new", RecordType::A, "192.0.2.1", None)];

    let plan = compute_import_plan(ImportMode::Append, &zone(), &rows, &want);

    assert!(plan.dels.is_empty());
    assert_eq!(added(&plan), ["192.0.2.1"]);
}

/// Verify that replace deletes every row the file does not name.
#[test]
fn replace_deletes_every_row_the_file_does_not_name() {
    let rows = [
        existing(1, "keep", RecordType::A, "192.0.2.1", 300),
        existing(2, "drop", RecordType::A, "192.0.2.9", 300),
        existing(3, "drop", RecordType::TXT, "\"x\"", 300),
    ];
    let want = [desired("keep", RecordType::A, "192.0.2.1", None)];

    let plan = compute_import_plan(ImportMode::Replace, &zone(), &rows, &want);

    assert_eq!(ids(&plan.dels), [2, 3]);
    assert_eq!(plan.unchanged, 1);
    assert!(plan.adds.is_empty());
}

/// Verify that upsert leaves names and types the file is silent about.
#[test]
fn upsert_leaves_names_and_types_the_file_is_silent_about() {
    // The file speaks about www/A only, so the other rows are none of its
    // business.
    let rows = [
        existing(1, "www", RecordType::A, "192.0.2.9", 300),
        existing(2, "www", RecordType::TXT, "\"x\"", 300),
        existing(3, "other", RecordType::A, "192.0.2.8", 300),
    ];
    let want = [desired("www", RecordType::A, "192.0.2.1", None)];

    let plan = compute_import_plan(ImportMode::Upsert, &zone(), &rows, &want);

    assert_eq!(ids(&plan.dels), [1]);
    assert_eq!(added(&plan), ["192.0.2.1"]);
}

/// Verify that a TTL change rewrites the row rather than editing it.
#[test]
fn a_ttl_change_rewrites_the_row_rather_than_editing_it() {
    // RFC 2181, Section 5.2: the records of one name and type share a TTL.
    let rows = [existing(1, "www", RecordType::A, "192.0.2.1", 300)];
    let want = [desired("www", RecordType::A, "192.0.2.1", Some(600))];

    let plan = compute_import_plan(ImportMode::Upsert, &zone(), &rows, &want);

    assert_eq!(ids(&plan.ttl_dels), [1]);
    assert_eq!(added(&plan), ["192.0.2.1"]);
    assert_eq!(plan.updated, 1);
    assert_eq!(plan.unchanged, 0);
}

/// Verify that append keeps a TTL it disagrees with.
#[test]
fn append_keeps_a_ttl_it_disagrees_with() {
    let rows = [existing(1, "www", RecordType::A, "192.0.2.1", 300)];
    let want = [desired("www", RecordType::A, "192.0.2.1", Some(600))];

    let plan = compute_import_plan(ImportMode::Append, &zone(), &rows, &want);

    assert!(plan.ttl_dels.is_empty());
    assert_eq!(plan.unchanged, 1);
}

/// Verify that an omitted TTL is the zones default not a wildcard.
#[test]
fn an_omitted_ttl_is_the_zones_default_not_a_wildcard() {
    // A file that leaves the TTL out still reconciles against the default,
    // so a row at another TTL is stale rather than unchanged.
    let rows = [existing(1, "www", RecordType::A, "192.0.2.1", 900)];
    let want = [desired("www", RecordType::A, "192.0.2.1", None)];

    let plan = compute_import_plan(ImportMode::Replace, &zone(), &rows, &want);

    assert_eq!(ids(&plan.ttl_dels), [1]);
    assert_eq!(plan.updated, 1);
}

/// Verify that a value the file spells differently is the same record.
#[test]
fn a_value_the_file_spells_differently_is_the_same_record() {
    let rows = [existing(
        1,
        "alias",
        RecordType::CNAME,
        "target.example.com.",
        300,
    )];
    let want = [desired(
        "alias",
        RecordType::CNAME,
        "Target.Example.COM",
        None,
    )];

    let plan = compute_import_plan(ImportMode::Replace, &zone(), &rows, &want);

    assert!(plan.dels.is_empty());
    assert_eq!(plan.unchanged, 1);
}
