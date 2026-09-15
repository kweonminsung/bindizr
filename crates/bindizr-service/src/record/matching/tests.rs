use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::*;

/// Build a record fixture with the requested fields.
fn record(record_type: RecordType, value: &str, priority: Option<i32>) -> Record {
    Record {
        id: 1,
        name: OwnerName::parse_in_zone("www", &ZoneName::parse("example.com").unwrap()).unwrap(),
        record_type,
        value: value.to_string(),
        ttl: 300,
        priority,
        created_at: Utc::now(),
        zone_id: 1,
    }
}

/// Verify that nothing given takes every record at the name.
#[test]
fn nothing_given_takes_every_record_at_the_name() {
    assert!(matches_record(
        &record(RecordType::A, "192.0.2.1", None),
        None,
        None,
        None
    ));
}

/// Verify that a type narrows to one RRSET.
#[test]
fn a_type_narrows_to_one_rrset() {
    let a = record(RecordType::A, "192.0.2.1", None);

    assert!(matches_record(&a, Some(&RecordType::A), None, None));
    assert!(!matches_record(&a, Some(&RecordType::TXT), None, None));
}

/// Verify that a value is compared canonically not as text.
#[test]
fn a_value_is_compared_canonically_not_as_text() {
    // The row stores the canonical spelling, so a request naming the same
    // record another way still names it.
    let cname = record(RecordType::CNAME, "target.example.com.", None);

    assert!(matches_record(
        &cname,
        Some(&RecordType::CNAME),
        Some("Target.Example.COM"),
        None
    ));
    assert!(!matches_record(
        &cname,
        Some(&RecordType::CNAME),
        Some("other.example.com"),
        None
    ));
}

/// Verify that a value never carries the preference.
#[test]
fn a_value_never_carries_the_preference() {
    // MX keeps its preference in its own column, so the value compares to the
    // exchange alone and two rows differing only in preference both match.
    let ten = record(RecordType::MX, "mail.example.com.", Some(10));
    let twenty = record(RecordType::MX, "mail.example.com.", Some(20));

    for row in [&ten, &twenty] {
        assert!(matches_record(
            row,
            Some(&RecordType::MX),
            Some("mail.example.com"),
            None
        ));
    }
}

/// Verify that a preference narrows where the value cannot.
#[test]
fn a_preference_narrows_where_the_value_cannot() {
    let ten = record(RecordType::MX, "mail.example.com.", Some(10));
    let twenty = record(RecordType::MX, "mail.example.com.", Some(20));

    assert!(matches_record(
        &ten,
        Some(&RecordType::MX),
        Some("mail.example.com"),
        Some(10)
    ));
    assert!(!matches_record(
        &twenty,
        Some(&RecordType::MX),
        Some("mail.example.com"),
        Some(10)
    ));
}

/// Verify that a preference asked of a type that has none matches nothing.
#[test]
fn a_preference_asked_of_a_type_that_has_none_matches_nothing() {
    assert!(!matches_record(
        &record(RecordType::A, "192.0.2.1", None),
        Some(&RecordType::A),
        None,
        Some(10)
    ));
}
