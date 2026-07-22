use chrono::Utc;

use super::*;
use crate::error::ErrorCode;

#[test]
fn normalize_pattern_defaults_to_match_any() {
    assert_eq!(normalize_pattern(None).unwrap(), "*");
    assert_eq!(normalize_pattern(Some("  ")).unwrap(), "*");
    assert_eq!(normalize_pattern(Some("@")).unwrap(), "@");
    assert_eq!(normalize_pattern(Some("*.Sub")).unwrap(), "*.sub");
    assert_eq!(normalize_pattern(Some("WWW")).unwrap(), "www");
}

#[test]
fn normalize_pattern_rejects_invalid_patterns() {
    for invalid in ["*.", "a*b", "*.a*", "bad name", "a..b", "*.**"] {
        let err = normalize_pattern(Some(invalid)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "input: {:?}", invalid);
    }
}

#[test]
fn normalize_types_parses_and_dedupes() {
    assert_eq!(normalize_types(None).unwrap(), "*");
    assert_eq!(normalize_types(Some("*")).unwrap(), "*");
    assert_eq!(
        normalize_types(Some(" a , txt ,A ")).unwrap(),
        "A,TXT".to_string()
    );

    let err = normalize_types(Some("A,BOGUS")).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn pattern_matching_covers_all_forms() {
    assert!(pattern_matches_name("*", "@"));
    assert!(pattern_matches_name("*", "anything.at.all"));

    assert!(pattern_matches_name("@", "@"));
    assert!(!pattern_matches_name("@", "www"));

    assert!(pattern_matches_name("www", "www"));
    assert!(pattern_matches_name("www", "WWW"));
    assert!(!pattern_matches_name("www", "sub.www"));

    assert!(pattern_matches_name("*.sub", "sub"));
    assert!(pattern_matches_name("*.sub", "a.sub"));
    assert!(pattern_matches_name("*.sub", "a.b.sub"));
    assert!(!pattern_matches_name("*.sub", "sub.other"));
    assert!(!pattern_matches_name("*.sub", "xsub"));
}

fn policy(pattern: &str, types: &str) -> ZoneTsigPolicy {
    ZoneTsigPolicy {
        id: 0,
        zone_id: 1,
        tsig_key_id: 1,
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

#[test]
fn authorize_update_requires_name_and_type_match() {
    let policies = vec![policy("*.dyn", "A,AAAA"), policy("@", "*")];

    assert!(authorize_update(
        &policies,
        "host.dyn",
        Some(&RecordType::A)
    ));
    assert!(authorize_update(&policies, "@", Some(&RecordType::TXT)));
    // Whole-name delete (TYPE ANY) is only covered by unrestricted types.
    assert!(authorize_update(&policies, "@", None));
    assert!(!authorize_update(&policies, "host.dyn", None));

    assert!(!authorize_update(
        &policies,
        "host.dyn",
        Some(&RecordType::TXT)
    ));
    assert!(!authorize_update(&policies, "www", Some(&RecordType::A)));
    assert!(!authorize_update(&policies, "", Some(&RecordType::A)));
}
