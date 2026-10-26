use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::{Serial, SoaInterval, Ttl};
use bindizr_core::model::record::RecordId;
use bindizr_core::model::zone::{Zone, ZoneId};
use chrono::Utc;

use super::*;
use crate::model::record::RecordType;

/// Build the test zone or its DNS name.
fn zone() -> Zone {
    Zone {
        id: ZoneId::from(1),
        name: ZoneName::parse("example.com").unwrap(),
        mname: "ns1.example.com".to_string(),
        rname: "admin@example.com".to_string(),
        default_ttl: Ttl::from_secs(300),
        serial: Serial::from(5),
        refresh: SoaInterval::from_secs(300),
        retry: SoaInterval::from_secs(60),
        expire: SoaInterval::from_secs(3600000),
        minimum_ttl: Ttl::from_secs(900),
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build an existing database record for import planning.
fn existing(id: i32, name: &str, record_type: RecordType, value: &str, ttl: i64) -> Record {
    Record {
        id: RecordId::from(id),
        name: OwnerName::parse_in_zone(name, &zone().name).unwrap(),
        record_type,
        value: value.to_string(),
        ttl: Ttl::try_from(ttl).unwrap(),
        priority: None,
        created_at: Utc::now(),
        zone_id: ZoneId::from(1),
    }
}

/// Build an imported record with its resolved TTL.
fn desired(name: &str, record_type: RecordType, value: &str, ttl: i64) -> DesiredRecord {
    DesiredRecord {
        source_name: name.to_string(),
        data: RecordData {
            name: OwnerName::parse_in_zone(name, &zone().name).unwrap(),
            record_type,
            value: value.to_string(),
            ttl: Ttl::try_from(ttl).unwrap(),
            priority: None,
        },
    }
}

/// Collect record IDs for import-plan assertions.
fn ids(records: &[Record]) -> Vec<RecordId> {
    records.iter().map(|record| record.id).collect()
}

/// Collect values added by an import plan.
fn added<'a>(plan: &ImportPlan<'a>) -> Vec<&'a str> {
    plan.adds
        .iter()
        .map(|desired_record| desired_record.data.value.as_str())
        .collect()
}

/// Verify that append never deletes what it did not ask about.
#[test]
fn append_preserves_records_absent_from_file() {
    let rows = [existing(1, "old", RecordType::A, "192.0.2.9", 300)];
    let want = [desired("new", RecordType::A, "192.0.2.1", 300)];

    let plan = ImportPlan::compute(ImportMode::Append, &rows, &want);

    assert!(plan.deletes.is_empty());
    assert_eq!(added(&plan), ["192.0.2.1"]);
}

/// Verify that replace deletes every row the file does not name.
#[test]
fn replace_deletes_records_absent_from_file() {
    let rows = [
        existing(1, "keep", RecordType::A, "192.0.2.1", 300),
        existing(2, "drop", RecordType::A, "192.0.2.9", 300),
        existing(3, "drop", RecordType::Txt, "\"x\"", 300),
    ];
    let want = [desired("keep", RecordType::A, "192.0.2.1", 300)];

    let plan = ImportPlan::compute(ImportMode::Replace, &rows, &want);

    assert_eq!(ids(&plan.deletes), [RecordId::from(2), RecordId::from(3)]);
    assert_eq!(plan.unchanged, 1);
    assert!(plan.adds.is_empty());
}

/// Verify that upsert leaves names and types the file is silent about.
#[test]
fn upsert_preserves_name_and_type_pairs_absent_from_file() {
    // The file speaks about www/A only, so the other rows are none of its
    // business.
    let rows = [
        existing(1, "www", RecordType::A, "192.0.2.9", 300),
        existing(2, "www", RecordType::Txt, "\"x\"", 300),
        existing(3, "other", RecordType::A, "192.0.2.8", 300),
    ];
    let want = [desired("www", RecordType::A, "192.0.2.1", 300)];

    let plan = ImportPlan::compute(ImportMode::Upsert, &rows, &want);

    assert_eq!(ids(&plan.deletes), [RecordId::from(1)]);
    assert_eq!(added(&plan), ["192.0.2.1"]);
}

/// Verify that a TTL change rewrites the row rather than editing it.
#[test]
fn import_plan_replaces_row_when_ttl_changes() {
    // RFC 2181, Section 5.2: the records of one name and type share a TTL.
    let rows = [existing(1, "www", RecordType::A, "192.0.2.1", 300)];
    let want = [desired("www", RecordType::A, "192.0.2.1", 600)];

    let plan = ImportPlan::compute(ImportMode::Upsert, &rows, &want);

    assert_eq!(ids(&plan.ttl_deletes), [RecordId::from(1)]);
    assert_eq!(added(&plan), ["192.0.2.1"]);
    assert_eq!(plan.updated, 1);
    assert_eq!(plan.unchanged, 0);
}

/// Verify that append keeps a TTL it disagrees with.
#[test]
fn append_keeps_a_ttl_it_disagrees_with() {
    let rows = [existing(1, "www", RecordType::A, "192.0.2.1", 300)];
    let want = [desired("www", RecordType::A, "192.0.2.1", 600)];

    let plan = ImportPlan::compute(ImportMode::Append, &rows, &want);

    assert!(plan.ttl_deletes.is_empty());
    assert_eq!(plan.unchanged, 1);
}

/// Verify that an omitted TTL is the zones default not a wildcard.
#[test]
fn import_plan_defaults_omitted_ttl_to_zone_default() {
    // A file that leaves the TTL out still reconciles against the default,
    // so a row at another TTL is stale rather than unchanged.
    let rows = [existing(1, "www", RecordType::A, "192.0.2.1", 900)];
    let want = [desired("www", RecordType::A, "192.0.2.1", 300)];

    let plan = ImportPlan::compute(ImportMode::Replace, &rows, &want);

    assert_eq!(ids(&plan.ttl_deletes), [RecordId::from(1)]);
    assert_eq!(plan.updated, 1);
}

/// Verify that a value the file spells differently is the same record.
#[test]
fn import_plan_matches_canonically_equivalent_values() {
    let rows = [existing(
        1,
        "alias",
        RecordType::Cname,
        "target.example.com.",
        300,
    )];
    let want = [desired(
        "alias",
        RecordType::Cname,
        "Target.Example.COM",
        300,
    )];

    let plan = ImportPlan::compute(ImportMode::Replace, &rows, &want);

    assert!(plan.deletes.is_empty());
    assert_eq!(plan.unchanged, 1);
}
