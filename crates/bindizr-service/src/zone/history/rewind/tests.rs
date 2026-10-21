use bindizr_core::{
    dns::{
        Ttl,
        name::{OwnerName, ZoneName},
    },
    model::{
        dnssec_record::DnssecRecordType,
        record::{RecordId, RecordType},
    },
};
use chrono::Utc;

use super::*;

/// Build a validated zone name for the test.
fn zone_name() -> ZoneName {
    ZoneName::parse("example.com").unwrap()
}

/// Build a record fixture with the requested fields.
fn record(id: i32, name: &str, value: &str) -> Record {
    Record {
        id: RecordId::from(id),
        name: OwnerName::parse_in_zone(name, &zone_name()).unwrap(),
        record_type: RecordType::A,
        value: value.to_string(),
        ttl: Ttl::from_secs(300),
        priority: None,
        created_at: Utc::now(),
        zone_id: ZoneId::from(1),
    }
}

/// Build a journal entry for a rewind test.
fn change(
    serial: i32,
    operation: ChangeOperation,
    name: &str,
    record_type: JournalRecordType,
    value: Option<&str>,
) -> ZoneChange {
    ZoneChange {
        zone_id: ZoneId::from(1),
        serial: Serial::try_from(serial).unwrap(),
        operation,
        record_name: OwnerName::parse_in_zone(name, &zone_name()).unwrap(),
        record_type,
        record_value: value.map(str::to_string),
        record_rdata: None,
        record_ttl: Ttl::from_secs(300),
        record_priority: None,
        derived: false,
    }
}

/// Wrap a user record type as a journal record type.
fn user(record_type: RecordType) -> JournalRecordType {
    JournalRecordType::User(record_type)
}

/// Collect rewound record values for comparison.
fn values(records: &[RecordData]) -> Vec<&str> {
    records.iter().map(|record| record.value.as_str()).collect()
}

/// Verify that undoing an add takes the record back out.
#[test]
fn rewind_removes_added_record() {
    let records = vec![record(1, "www", "192.0.2.1"), record(2, "www", "192.0.2.2")];
    let changes = [change(
        5,
        ChangeOperation::Add,
        "www",
        user(RecordType::A),
        Some("192.0.2.2"),
    )];

    assert_eq!(values(&undo_changes(records, &changes)), ["192.0.2.1"]);
}

/// Verify that undoing a delete restores the row the journal kept.
#[test]
fn rewind_restores_deleted_record_from_journal() {
    let changes = [change(
        5,
        ChangeOperation::Delete,
        "www",
        user(RecordType::A),
        Some("192.0.2.9"),
    )];

    let restored = undo_changes(Vec::new(), &changes);

    assert_eq!(values(&restored), ["192.0.2.9"]);
    assert_eq!(restored[0].ttl, Ttl::from_secs(300));
}

/// Verify that only one of two identical records comes out.
#[test]
fn rewind_removes_only_one_identical_record() {
    // The match key ignores row identity, so an undone ADD takes one of the
    // two rows, not both.
    let records = vec![record(1, "www", "192.0.2.1"), record(2, "www", "192.0.2.1")];
    let changes = [change(
        5,
        ChangeOperation::Add,
        "www",
        user(RecordType::A),
        Some("192.0.2.1"),
    )];

    assert_eq!(values(&undo_changes(records, &changes)), ["192.0.2.1"]);
}

/// Verify that a value spelled differently still matches its row.
#[test]
fn rewind_matches_canonically_equivalent_values() {
    // The key canonicalizes, so a value the journal spelled in another case
    // still names its row.
    let mut live = record(1, "alias", "Target.Example.COM.");
    live.record_type = RecordType::Cname;
    let changes = [change(
        5,
        ChangeOperation::Add,
        "alias",
        user(RecordType::Cname),
        Some("target.example.com"),
    )];

    assert!(undo_changes(vec![live], &changes).is_empty());
}

/// Verify that a record added and deleted inside the window leaves nothing.
#[test]
fn rewind_omits_records_added_and_deleted_inside_window() {
    let changes = [
        change(
            5,
            ChangeOperation::Add,
            "tmp",
            user(RecordType::A),
            Some("192.0.2.5"),
        ),
        change(
            6,
            ChangeOperation::Delete,
            "tmp",
            user(RecordType::A),
            Some("192.0.2.5"),
        ),
    ];

    assert!(undo_changes(Vec::new(), &changes).is_empty());
}

/// Verify that derived and SOA rows are not user data to restore.
#[test]
fn rewind_excludes_derived_and_soa_records() {
    // Rollback re-signs the derived plane, and the SOA lives in the version
    // row, so neither belongs in the rewound records.
    let changes = [
        change(
            5,
            ChangeOperation::Delete,
            "@",
            JournalRecordType::Derived(DnssecRecordType::Rrsig),
            Some("ignored"),
        ),
        change(
            5,
            ChangeOperation::Delete,
            "@",
            JournalRecordType::Soa,
            None,
        ),
    ];

    assert!(undo_changes(Vec::new(), &changes).is_empty());
}

/// Verify that a history that does not add up does not block the rollback.
#[test]
fn rewind_accepts_incomplete_history() {
    // Two anomalies at once: an ADD with no live row to take, and a user row
    // carrying no value.
    let changes = [
        change(
            5,
            ChangeOperation::Add,
            "gone",
            user(RecordType::A),
            Some("192.0.2.1"),
        ),
        change(6, ChangeOperation::Add, "www", user(RecordType::A), None),
    ];

    assert_eq!(
        values(&undo_changes(
            vec![record(1, "keep", "192.0.2.7")],
            &changes
        )),
        ["192.0.2.7"]
    );
}

/// Verify that the output order does not follow the hash map.
#[test]
fn rewind_returns_deterministic_record_order() {
    let records = vec![
        record(1, "zzz", "192.0.2.3"),
        record(2, "aaa", "192.0.2.1"),
        record(3, "mmm", "192.0.2.2"),
    ];

    let sorted = undo_changes(records, &[]);

    assert_eq!(values(&sorted), ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
}
