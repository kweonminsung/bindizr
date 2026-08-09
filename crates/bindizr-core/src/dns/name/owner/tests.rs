use super::{OwnerName, ParseNameError, ZoneName};

fn zone() -> ZoneName {
    ZoneName::parse("test.example.com").unwrap()
}

#[test]
fn zone_name_parse_normalizes_case_and_the_trailing_dot() {
    assert_eq!(
        ZoneName::parse("Example.COM.").unwrap().as_str(),
        "example.com"
    );
    assert_eq!(
        ZoneName::parse("  example.com  ").unwrap().as_str(),
        "example.com"
    );
    assert_eq!(
        ZoneName::parse("example.com").unwrap().to_fqdn(),
        "example.com."
    );
}

#[test]
fn zone_name_parse_rejects_malformed_names() {
    for (value, expected) in [
        ("", ParseNameError::Empty),
        (".", ParseNameError::Empty),
        ("a b.com", ParseNameError::Whitespace),
    ] {
        assert_eq!(ZoneName::parse(value).unwrap_err(), expected, "{value:?}");
    }

    // Per-label problems keep the detail the label check phrased. Underscore
    // labels are refused here but accepted as owner names.
    for value in ["bad..example.com", "_svc.example.com", "-bad.example.com"] {
        assert!(
            matches!(
                ZoneName::parse(value).unwrap_err(),
                ParseNameError::InvalidLabel(_)
            ),
            "{value:?}"
        );
    }
}

#[test]
fn owner_name_parse_reduces_input_to_the_stored_form() {
    let zone = zone();

    assert_eq!(OwnerName::parse_in_zone("@", &zone).unwrap().as_str(), "@");
    assert_eq!(
        OwnerName::parse_in_zone("a1", &zone).unwrap().as_str(),
        "a1"
    );
    assert_eq!(
        OwnerName::parse_in_zone("A1.Test.Example.Com", &zone)
            .unwrap()
            .as_str(),
        "a1"
    );
    assert_eq!(
        OwnerName::parse_in_zone("A1.Test.Example.Com.", &zone)
            .unwrap()
            .as_str(),
        "a1"
    );
    // Owner names must admit the `_`-prefixed labels ACME and SRV rely on.
    assert_eq!(
        OwnerName::parse_in_zone("_acme-challenge", &zone)
            .unwrap()
            .as_str(),
        "_acme-challenge"
    );
}

#[test]
fn owner_name_parse_rejects_names_outside_the_zone() {
    let zone = zone();

    for name in [
        "a1.",
        "example.com.",
        "a1.example.com.",
        "other.com.",
        "badtest.example.com.",
    ] {
        assert_eq!(
            OwnerName::parse_in_zone(name, &zone).unwrap_err(),
            ParseNameError::OutsideZone,
            "{name:?}"
        );
    }
}

#[test]
fn owner_name_equality_and_hashing_fold_case() {
    use std::collections::HashSet;

    assert_eq!(OwnerName::from_row("WWW"), OwnerName::from_row("www"));
    assert!(OwnerName::from_row("@").is_apex());

    let mut seen = HashSet::new();
    seen.insert(OwnerName::from_row("WWW"));
    assert!(seen.contains(&OwnerName::from_row("www")));
}

#[test]
fn owner_name_to_fqdn_resolves_within_its_zone() {
    let zone = zone();

    assert_eq!(OwnerName::apex().to_fqdn(&zone), "test.example.com.");
    assert_eq!(
        OwnerName::from_row("a1").to_fqdn(&zone),
        "a1.test.example.com."
    );
}

#[test]
fn owner_name_prefixed_escapes_a_dotted_label() {
    let apex = OwnerName::apex();

    assert_eq!(apex.prefixed("www").as_str(), "www");
    assert_eq!(
        OwnerName::from_row("sub").prefixed("www").as_str(),
        "www.sub"
    );
    // A dot inside the label is content, not a new boundary.
    assert_eq!(apex.prefixed("a.b").as_str(), r"a\.b");
}
