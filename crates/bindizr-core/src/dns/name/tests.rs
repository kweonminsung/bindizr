use super::{
    OwnerName, ParseNameError, ZoneName, classify_wire_labels, is_same_or_subdomain_fqdn,
    to_display_owner_fqdn, to_encoded_owner_name, to_lookup_name, to_owner_fqdn,
};

#[test]
fn wire_labels_reject_an_escape_anywhere_in_the_name() {
    // Refusing the escape is what makes every later '.' split exact, so it is
    // checked before the label rules it would otherwise distort.
    for name in [
        r"host\.name.example.com",
        r"bad.example.com\",
        r"a\\b.example.com",
    ] {
        assert_eq!(
            classify_wire_labels(name).unwrap_err(),
            ParseNameError::Escape,
            "{name:?}"
        );
    }

    assert!(classify_wire_labels("host.example.com").is_ok());
    assert!(classify_wire_labels("_acme-challenge.example.com.").is_ok());
}

#[test]
fn to_owner_fqdn_expands_relative_name() {
    assert_eq!(to_owner_fqdn("sub", "example.com"), "sub.example.com.");
    assert_eq!(to_owner_fqdn("www", "example.com."), "www.example.com.");
}

#[test]
fn to_owner_fqdn_keeps_zone_qualified_name() {
    assert_eq!(
        to_owner_fqdn("www.example.com", "example.com."),
        "www.example.com."
    );
    assert_eq!(to_owner_fqdn("example.com", "example.com."), "example.com.");
}

#[test]
fn to_owner_fqdn_handles_fqdn_and_apex() {
    assert_eq!(to_owner_fqdn("sub.", "example.com."), "sub.");
    assert_eq!(
        to_owner_fqdn("api.example.com.", "example.com"),
        "api.example.com."
    );
    assert_eq!(to_owner_fqdn("@", "example.com."), "example.com.");
}

#[test]
fn to_encoded_owner_name_maps_apex_and_subnames_lowercased() {
    assert_eq!(
        to_encoded_owner_name("example.com.", "example.com").as_deref(),
        Some("@")
    );
    assert_eq!(
        to_encoded_owner_name("@", "example.com.").as_deref(),
        Some("@")
    );
    assert_eq!(
        to_encoded_owner_name("WWW.Example.COM.", "example.com").as_deref(),
        Some("www")
    );
    assert_eq!(
        to_encoded_owner_name("a.b.example.com.", "example.com.").as_deref(),
        Some("a.b")
    );
    assert_eq!(
        to_encoded_owner_name("mail", "example.com").as_deref(),
        Some("mail")
    );
}

#[test]
fn to_encoded_owner_name_strips_the_zone_suffix_once() {
    // Repeated stripping collapsed a repeated-zone owner to an empty name.
    assert_eq!(
        to_encoded_owner_name("example.com.example.com.", "example.com").as_deref(),
        Some("example.com")
    );
}

#[test]
fn to_encoded_owner_name_rejects_names_outside_the_zone() {
    assert_eq!(to_encoded_owner_name("other.org.", "example.com"), None);
    assert_eq!(to_encoded_owner_name("aexample.com.", "example.com"), None);
}

#[test]
fn an_escaped_name_never_reaches_zone_containment() {
    // Escapes are refused at the parse boundary, so containment only ever
    // sees names whose every '.' is a real label boundary.
    let zone = ZoneName::parse("example.com").unwrap();
    assert_eq!(
        OwnerName::parse_in_zone(r"evil\.example.com.", &zone).unwrap_err(),
        ParseNameError::Escape
    );
    assert_eq!(
        to_lookup_name(r"evil\.example.com").unwrap_err(),
        ParseNameError::Escape
    );
}

#[test]
fn zone_containment_compares_whole_labels() {
    assert!(is_same_or_subdomain_fqdn(
        "www.example.com.",
        "example.com."
    ));
    assert!(is_same_or_subdomain_fqdn("example.com.", "example.com."));
    assert!(!is_same_or_subdomain_fqdn("aexample.com.", "example.com."));
    assert!(!is_same_or_subdomain_fqdn(
        "example.com.",
        "www.example.com."
    ));
}

#[test]
fn to_display_owner_fqdn_lowercases_and_qualifies() {
    let zone = "test.example.com";

    assert_eq!(to_display_owner_fqdn("@", zone), "test.example.com.");
    assert_eq!(to_display_owner_fqdn("a1", zone), "a1.test.example.com.");
    assert_eq!(
        to_display_owner_fqdn("_acme-challenge", zone),
        "_acme-challenge.test.example.com."
    );
    assert_eq!(
        to_display_owner_fqdn("A1.Test.Example.Com.", zone),
        "a1.test.example.com."
    );
}

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

    // Underscore labels are refused here but accepted as owner names.
    for (value, expected) in [
        ("bad..example.com", ParseNameError::EmptyLabel),
        (
            "_svc.example.com",
            ParseNameError::LabelCharset {
                underscore_allowed: false,
            },
        ),
        ("-bad.example.com", ParseNameError::LabelHyphen),
    ] {
        assert_eq!(ZoneName::parse(value).unwrap_err(), expected, "{value:?}");
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
