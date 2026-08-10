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
fn an_escaped_trailing_dot_is_label_data_not_the_root() {
    // Trimming the dot off the text first would leave a dangling escape.
    assert_eq!(decode_name_labels(r"a\.").unwrap(), vec!["a."]);
    assert_eq!(decode_name_labels("www.example.com.").unwrap().len(), 3);

    let zone = ZoneName::parse("example.com").unwrap();
    assert_eq!(
        OwnerName::parse_in_zone(r"a\.", &zone).unwrap().labels(),
        ["a."]
    );
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

    // Rows hold the apex out of band, so no label can spell it.
    assert_eq!(
        OwnerName::parse_in_zone("@", &zone).unwrap().to_stored(),
        ""
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
fn owner_name_parse_enforces_the_length_limit_on_both_paths() {
    let zone = ZoneName::parse("example.com").unwrap();
    let long = vec!["a".repeat(60); 5].join(".");

    // The qualified name is what has to fit, so relative and absolute input
    // must reach the same verdict.
    assert_eq!(
        OwnerName::parse_in_zone(&long, &zone).unwrap_err(),
        ParseNameError::TooLong
    );
    assert_eq!(
        OwnerName::parse_in_zone(&format!("{long}.example.com."), &zone).unwrap_err(),
        ParseNameError::TooLong
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
    assert!(OwnerName::from_row("").is_apex());

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

// The invariant the type rests on: whatever a constructor accepts comes back
// unchanged through storage and through the wire. `@` broke the first and a
// `\DDD` whitespace escape the second.
#[test]
fn every_accepted_owner_name_survives_storage_and_the_wire() {
    let zone = zone();

    for input in [
        "@",
        "a1",
        "_acme-challenge",
        "*",
        "*.sub",
        "sub.deep",
        r"host\.name",
        r"a\\b",
        r"\064",
        r"\@",
        r"host\032name",
        "A1.Test.Example.Com.",
    ] {
        let Ok(owner) = OwnerName::parse_in_zone(input, &zone) else {
            continue;
        };

        assert_eq!(
            OwnerName::from_row(&owner.to_stored()),
            owner,
            "storage round trip for {input:?}"
        );
        assert_eq!(
            OwnerName::parse_absolute_in_zone(&owner.to_fqdn(&zone), &zone).as_ref(),
            Ok(&owner),
            "wire round trip for {input:?}"
        );
    }
}

// Both owner constructors admit the same names; only how they treat a name
// outside the zone differs.
#[test]
fn owner_name_constructors_admit_the_same_labels() {
    let zone = zone();

    for label in ["host name", r"host\032name", "host\u{7}bell"] {
        let relative = OwnerName::parse_in_zone(label, &zone);
        let absolute =
            OwnerName::parse_absolute_in_zone(&format!("{label}.test.example.com."), &zone);
        assert_eq!(relative, Err(ParseNameError::Whitespace), "{label:?}");
        assert_eq!(absolute, Err(ParseNameError::Whitespace), "{label:?}");
    }
}

// RFC 1035, Section 2.3.4 bounds the wire form at 255 octets, not the 253 the
// presentation form is measured by.
#[test]
fn owner_name_admits_a_maximum_length_name() {
    let zone = ZoneName::parse("example.com").unwrap();
    let longest = format!(
        "{}.{}.{}.{}.example.com.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(49)
    );
    assert_eq!(longest.trim_end_matches('.').len(), 253);

    assert!(OwnerName::parse_absolute_in_zone(&longest, &zone).is_ok());
    let over = longest.replace(&"d".repeat(49), &"d".repeat(50));
    assert_eq!(
        OwnerName::parse_absolute_in_zone(&over, &zone),
        Err(ParseNameError::TooLong)
    );
}

// A master file ends the owner field at any of these, so an unescaped one
// would truncate the record or comment out the rest of the line.
#[test]
fn owner_name_escapes_master_file_metacharacters() {
    let zone = ZoneName::parse("example.com").unwrap();

    for (input, rendered) in [
        ("foo;bar", r"foo\;bar"),
        ("foo(bar", r"foo\(bar"),
        ("foo)bar", r"foo\)bar"),
        ("foo\"bar", "foo\\\"bar"),
        ("$origin", r"\$origin"),
    ] {
        let owner = OwnerName::parse_in_zone(input, &zone).unwrap();
        assert_eq!(owner.to_string(), rendered, "{input:?}");
    }
}

// The wire limit applies to decoded labels but rows hold the escaped form, so
// the column must fit the escaped worst case. Keep in step with the DB schema.
#[test]
fn worst_case_stored_form_fits_the_schema_column_width() {
    const SCHEMA_COLUMN_WIDTH: usize = 512;
    let zone = ZoneName::parse("e.co").unwrap();

    // Every `$` escapes, doubling each label; four is the split that maximizes
    // the rendering under the 63-byte label cap and the wire budget.
    let labels = [
        "$".repeat(63),
        "$".repeat(63),
        "$".repeat(63),
        "$".repeat(56),
    ];
    let decoded: usize = labels.iter().map(String::len).sum();

    let owner = OwnerName::parse_in_zone(&labels.join("."), &zone)
        .expect("the largest name the wire limit admits inside this zone");
    let stored = owner.to_stored();

    assert_eq!(stored.len(), decoded * 2 + labels.len() - 1);
    assert!(
        stored.len() <= SCHEMA_COLUMN_WIDTH,
        "stored form is {} bytes, column holds {}",
        stored.len(),
        SCHEMA_COLUMN_WIDTH
    );

    // One more byte of name is refused, so nothing longer can reach a row.
    let mut longer = labels.to_vec();
    longer[3].push('$');
    assert_eq!(
        OwnerName::parse_in_zone(&longer.join("."), &zone),
        Err(ParseNameError::TooLong)
    );
}
