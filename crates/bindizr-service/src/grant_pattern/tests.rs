use bindizr_core::dns::name::{OwnerName, ZoneName};

use super::*;
use crate::error::ErrorCode;

/// Verify that `normalize_pattern` defaults to match any.
#[test]
fn normalize_pattern_defaults_to_match_any() {
    assert_eq!(normalize_pattern(None).unwrap(), "*");
    assert_eq!(normalize_pattern(Some("  ")).unwrap(), "*");
    assert_eq!(normalize_pattern(Some("@")).unwrap(), "@");
    assert_eq!(normalize_pattern(Some("*.Sub")).unwrap(), "*.sub");
    assert_eq!(normalize_pattern(Some("WWW")).unwrap(), "www");
}

/// Verify that `normalize_pattern` rejects invalid patterns.
#[test]
fn normalize_pattern_rejects_invalid_patterns() {
    // The last three are refused by name decoding, not re-checked here.
    let long_label = "x".repeat(64);
    for invalid in ["*.", "a*b", "*.a*", "bad name", "a..b", "*.**", &long_label] {
        let err = normalize_pattern(Some(invalid)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "input: {:?}", invalid);
    }
}

/// Verify that normalize types parses and dedupes.
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

/// Verify that pattern matching covers all forms.
#[test]
fn pattern_matching_covers_all_forms() {
    assert!(matches_name("*", &OwnerName::apex()));
    assert!(matches_name("*", &OwnerName::from_row("anything.at.all")));

    assert!(matches_name("@", &OwnerName::apex()));
    assert!(!matches_name("@", &OwnerName::from_row("www")));

    assert!(matches_name("www", &OwnerName::from_row("www")));
    assert!(matches_name("www", &OwnerName::from_row("WWW")));
    assert!(!matches_name("www", &OwnerName::from_row("sub.www")));

    assert!(matches_name("*.sub", &OwnerName::from_row("sub")));
    assert!(matches_name("*.sub", &OwnerName::from_row("a.sub")));
    assert!(matches_name("*.sub", &OwnerName::from_row("a.b.sub")));
    assert!(!matches_name("*.sub", &OwnerName::from_row("sub.other")));
    assert!(!matches_name("*.sub", &OwnerName::from_row("xsub")));
}

/// Verify that `normalize_pattern` canonicalizes escapes and rejects malformed ones.
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

/// Verify that a subtree grant does not reach a label that merely spells it.
#[test]
fn a_subtree_grant_does_not_reach_a_label_that_merely_spells_it() {
    // `a\.sub` is the single label `a.sub`, not a name under `sub`.
    assert!(!matches_name("*.sub", &OwnerName::from_row(r"a\.sub")));
    assert!(matches_name("*.sub", &OwnerName::from_row(r"a\.b.sub")));
}

/// Verify rejection of wildcard grant labels, including escaped spellings.
///
/// Normalizing `\042` to `*` would widen a literal-owner grant into a match-all or subtree
/// grant.
#[test]
fn rejects_a_wildcard_label_however_it_is_spelled() {
    for pattern in [r"\042", r"\042.sub", r"\042x", r"a\042b", "a*b", "*x"] {
        let err = normalize_pattern(Some(pattern)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{pattern} was accepted");
    }

    // The two spellings the language does define keep working.
    assert_eq!(normalize_pattern(Some("*")).unwrap(), "*");
    assert_eq!(normalize_pattern(Some("*.sub")).unwrap(), "*.sub");
}

/// Verify that an escaped `@` remains a literal owner by retaining its escape through
/// normalization.
#[test]
fn an_escaped_at_stays_a_literal_owner() {
    let pattern = normalize_pattern(Some(r"\064")).unwrap();
    assert_eq!(pattern, r"\@");
    assert!(!matches_name(&pattern, &OwnerName::apex()));
}

/// Verify that an escaped trailing dot remains part of a relative label.
///
/// A text-only trailing-dot check would mistake the single label `a.` for an absolute name.
#[test]
fn an_escaped_dot_is_label_data_not_a_root_marker() {
    assert_eq!(normalize_pattern(Some(r"a\.")).unwrap(), r"a\.");

    // A real trailing dot still is: a pattern is relative to its zone.
    assert_eq!(
        normalize_pattern(Some("sub.")).unwrap_err().code,
        ErrorCode::InvalidInput
    );
}

/// Verify that a pattern becomes the name a domain filter can spell.
#[test]
fn a_pattern_becomes_the_name_a_domain_filter_can_spell() {
    let zone = ZoneName::parse("example.com").unwrap();

    assert_eq!(pattern_domain("*", &zone), "example.com.");
    assert_eq!(pattern_domain("*.k8s", &zone), "k8s.example.com.");
    assert_eq!(pattern_domain("a.b", &zone), "a.b.example.com.");

    // Both widen: a filter entry always carries everything under it, so the
    // apex reads as the zone and an exact name as its subtree.
    assert_eq!(pattern_domain("@", &zone), "example.com.");
    assert_eq!(pattern_domain("www", &zone), "www.example.com.");
}
