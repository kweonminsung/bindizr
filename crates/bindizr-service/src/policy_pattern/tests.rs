use bindizr_core::dns::name::OwnerName;

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
    assert!(pattern_matches_name("*", &OwnerName::from_row("@")));
    assert!(pattern_matches_name(
        "*",
        &OwnerName::from_row("anything.at.all")
    ));

    assert!(pattern_matches_name("@", &OwnerName::from_row("@")));
    assert!(!pattern_matches_name("@", &OwnerName::from_row("www")));

    assert!(pattern_matches_name("www", &OwnerName::from_row("www")));
    assert!(pattern_matches_name("www", &OwnerName::from_row("WWW")));
    assert!(!pattern_matches_name(
        "www",
        &OwnerName::from_row("sub.www")
    ));

    assert!(pattern_matches_name("*.sub", &OwnerName::from_row("sub")));
    assert!(pattern_matches_name("*.sub", &OwnerName::from_row("a.sub")));
    assert!(pattern_matches_name(
        "*.sub",
        &OwnerName::from_row("a.b.sub")
    ));
    assert!(!pattern_matches_name(
        "*.sub",
        &OwnerName::from_row("sub.other")
    ));
    assert!(!pattern_matches_name("*.sub", &OwnerName::from_row("xsub")));
}

#[test]
fn normalize_pattern_canonicalizes_escapes_and_rejects_malformed_ones() {
    // A pattern is stored canonically so one name has one spelling, and
    // matching decodes it back to labels.
    assert_eq!(normalize_pattern(Some(r"a\046sub")).unwrap(), r"a\.sub");
    assert_eq!(normalize_pattern(Some(r"*.a\.b")).unwrap(), r"*.a\.b");

    for invalid in [r"a\", "www.", "*.sub."] {
        let err = normalize_pattern(Some(invalid)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "input: {:?}", invalid);
    }
}

#[test]
fn a_subtree_grant_does_not_reach_a_label_that_merely_spells_it() {
    // `a\.sub` is the single label `a.sub`, not a name under `sub`.
    assert!(!pattern_matches_name(
        "*.sub",
        &OwnerName::from_row(r"a\.sub")
    ));
    assert!(pattern_matches_name(
        "*.sub",
        &OwnerName::from_row(r"a\.b.sub")
    ));
}
