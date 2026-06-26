use chrono::Utc;

use super::matches_record_search;
use crate::model::record::{Record, RecordType};

fn test_record() -> Record {
    Record {
        id: 1,
        name: "www".to_string(),
        record_type: RecordType::A,
        value: "192.0.2.10".to_string(),
        ttl: Some(3600),
        priority: None,
        created_at: Utc::now(),
        zone_id: 1,
    }
}

#[test]
fn matches_record_search_treats_empty_search_as_no_filter() {
    let record = test_record();

    assert!(matches_record_search(
        &record,
        "example.com",
        "www.example.com.",
        "192.0.2.10",
        Some("")
    ));
    assert!(matches_record_search(
        &record,
        "example.com",
        "www.example.com.",
        "192.0.2.10",
        Some(".")
    ));
}

#[test]
fn matches_record_search_filters_non_empty_search() {
    let record = test_record();

    assert!(matches_record_search(
        &record,
        "example.com",
        "www.example.com.",
        "192.0.2.10",
        Some("www")
    ));
    assert!(!matches_record_search(
        &record,
        "example.com",
        "www.example.com.",
        "192.0.2.10",
        Some("missing")
    ));
}
