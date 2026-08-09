use super::{
    OwnerName, ParseNameError, ZoneName, decode_name_labels, labels_in_zone, to_lookup_name,
};

fn zone() -> ZoneName {
    ZoneName::parse("test.example.com").unwrap()
}

#[test]
fn decode_keeps_an_escaped_dot_inside_one_label() {
    assert_eq!(
        decode_name_labels(r"host\.name.example.com").unwrap(),
        vec!["host.name", "example", "com"]
    );
    assert_eq!(
        decode_name_labels(r"back\\slash.example.com").unwrap(),
        vec![r"back\slash", "example", "com"]
    );
}

#[test]
fn decode_resolves_decimal_escapes() {
    // BIND writes `\DDD` for octets with no plain spelling, so one name can
    // arrive either way (RFC 1035, Section 5.1).
    assert_eq!(decode_name_labels(r"a\046b.example.com").unwrap()[0], "a.b");
    assert_eq!(decode_name_labels(r"a\098c.example.com").unwrap()[0], "abc");
}

#[test]
fn decode_rejects_malformed_escapes() {
    for (name, expected) in [
        (r"bad.example.com\", ParseNameError::DanglingEscape),
        (r"a\04.example.com", ParseNameError::InvalidEscape),
        (r"a\300.example.com", ParseNameError::InvalidEscape),
        (r"a\255b.example.com", ParseNameError::NonUtf8Label),
        ("bad..example.com", ParseNameError::EmptyLabel),
    ] {
        assert_eq!(decode_name_labels(name).unwrap_err(), expected, "{name:?}");
    }
}

#[test]
fn lookup_name_canonicalizes_spelling_and_case() {
    // Two spellings of one name must reach the database as one string: the
    // record filter compares them as text.
    assert_eq!(
        to_lookup_name(r"A\046B.Example.COM.").unwrap(),
        r"a\.b.example.com"
    );
    assert_eq!(
        to_lookup_name(r"a\.b.example.com").unwrap(),
        r"a\.b.example.com"
    );
    assert_eq!(
        to_lookup_name("  app.example.com  ").unwrap(),
        "app.example.com"
    );

    assert_eq!(to_lookup_name("").unwrap_err(), ParseNameError::Empty);
    assert_eq!(to_lookup_name(".").unwrap_err(), ParseNameError::Empty);
    assert_eq!(
        to_lookup_name("bad name.example.com").unwrap_err(),
        ParseNameError::Whitespace
    );
}

#[test]
fn containment_compares_whole_labels() {
    let labels = |name: &str| decode_name_labels(name).unwrap();

    assert!(labels_in_zone(
        &labels("www.example.com"),
        &labels("example.com")
    ));
    assert!(labels_in_zone(
        &labels("example.com"),
        &labels("example.com")
    ));
    assert!(!labels_in_zone(
        &labels("aexample.com"),
        &labels("example.com")
    ));
    assert!(!labels_in_zone(
        &labels("example.com"),
        &labels("www.example.com")
    ));

    // [evil.example, com] is one label short of being inside example.com; a
    // text suffix test would say it is.
    assert!(!labels_in_zone(
        &labels(r"evil\.example.com"),
        &labels("example.com")
    ));
}

#[test]
fn owner_name_parse_reduces_input_to_the_stored_form() {
    let zone = zone();

    assert_eq!(
        OwnerName::parse_in_zone("@", &zone).unwrap().to_stored(),
        "@"
    );
    assert_eq!(
        OwnerName::parse_in_zone("a1", &zone).unwrap().to_stored(),
        "a1"
    );
    assert_eq!(
        OwnerName::parse_in_zone("A1.Test.Example.Com", &zone)
            .unwrap()
            .to_stored(),
        "a1"
    );
    assert_eq!(
        OwnerName::parse_in_zone("A1.Test.Example.Com.", &zone)
            .unwrap()
            .to_stored(),
        "a1"
    );
    // Owner names must admit the `_`-prefixed labels ACME and SRV rely on.
    assert_eq!(
        OwnerName::parse_in_zone("_acme-challenge", &zone)
            .unwrap()
            .to_stored(),
        "_acme-challenge"
    );
}

#[test]
fn owner_name_parse_strips_the_zone_suffix_once() {
    let zone = ZoneName::parse("example.com").unwrap();

    // Stripping the suffix more than once would leave this owner empty.
    assert_eq!(
        OwnerName::parse_in_zone("example.com.example.com.", &zone)
            .unwrap()
            .to_stored(),
        "example.com"
    );
}

#[test]
fn owner_name_keeps_an_escaped_dot_as_label_data() {
    let zone = ZoneName::parse("example.com").unwrap();

    let owner = OwnerName::parse_in_zone(r"host\.name.example.com.", &zone).unwrap();
    assert_eq!(owner.labels(), ["host.name"]);
    assert_eq!(owner.to_stored(), r"host\.name");
    assert_eq!(owner.to_fqdn(&zone), r"host\.name.example.com.");

    // The same name spelled with a decimal escape is the same owner.
    assert_eq!(
        OwnerName::parse_in_zone(r"host\046name.example.com.", &zone).unwrap(),
        owner
    );

    // One label that merely spells the zone is not inside it.
    assert_eq!(
        OwnerName::parse_in_zone(r"evil\.example.com.", &zone).unwrap_err(),
        ParseNameError::OutsideZone
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
fn owner_name_parse_absolute_never_qualifies_a_foreign_name() {
    let zone = ZoneName::parse("example.com").unwrap();

    // Lookup-form input carries no trailing dot, so only this entry point can
    // tell `app.other.org` apart from a relative name.
    assert_eq!(
        OwnerName::parse_absolute_in_zone("app.other.org", &zone).unwrap_err(),
        ParseNameError::OutsideZone
    );
    assert_eq!(
        OwnerName::parse_absolute_in_zone("app.example.com", &zone)
            .unwrap()
            .to_stored(),
        "app"
    );
    assert!(
        OwnerName::parse_absolute_in_zone("example.com", &zone)
            .unwrap()
            .is_apex()
    );
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
    assert_eq!(
        OwnerName::from_row("A1.Sub").to_fqdn(&zone),
        "a1.sub.test.example.com."
    );
}

#[test]
fn owner_name_is_same_or_under_compares_labels() {
    let sub = OwnerName::from_row("sub");

    assert!(OwnerName::from_row("a.sub").is_same_or_under(&sub));
    assert!(sub.is_same_or_under(&sub));
    assert!(!OwnerName::from_row("xsub").is_same_or_under(&sub));
    // `a\.sub` is the single label `a.sub`, so it is not under `sub`.
    assert!(!OwnerName::from_row(r"a\.sub").is_same_or_under(&sub));
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

    // Underscore labels are refused here but accepted as owner names. The same
    // LDH rule is what keeps escapes out of zone names entirely.
    for (value, expected) in [
        ("bad..example.com", ParseNameError::EmptyLabel),
        (
            "_svc.example.com",
            ParseNameError::LabelCharset {
                underscore_allowed: false,
            },
        ),
        (
            r"evil\.example.com",
            ParseNameError::LabelCharset {
                underscore_allowed: false,
            },
        ),
        ("-bad.example.com", ParseNameError::LabelHyphen),
    ] {
        assert_eq!(ZoneName::parse(value).unwrap_err(), expected, "{value:?}");
    }
}
