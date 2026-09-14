use super::{
    OwnerName, ParseNameError, ZoneName, decode_name_labels, encode_name, escape_non_ascii,
    is_label_suffix, to_lookup_name,
};

/// Build the test zone or its DNS name.
fn zone() -> ZoneName {
    ZoneName::parse("test.example.com").unwrap()
}

/// Verify that `decode` keeps an escaped dot inside one label.
#[test]
fn decode_keeps_an_escaped_dot_inside_one_label() {
    assert_eq!(
        decode_name_labels(r"host\.name.example.com").unwrap().0,
        vec!["host.name", "example", "com"]
    );
    assert_eq!(
        decode_name_labels(r"back\\slash.example.com").unwrap().0,
        vec![r"back\slash", "example", "com"]
    );
}

/// Verify that `decode` resolves decimal escapes.
#[test]
fn decode_resolves_decimal_escapes() {
    // BIND writes `\DDD` for octets with no plain spelling, so one name can
    // arrive either way (RFC 1035, Section 5.1).
    assert_eq!(
        decode_name_labels(r"a\046b.example.com").unwrap().0[0],
        "a.b"
    );
    assert_eq!(
        decode_name_labels(r"a\098c.example.com").unwrap().0[0],
        "abc"
    );
}

/// Verify that an escaped trailing dot is label data not the root.
#[test]
fn an_escaped_trailing_dot_is_label_data_not_the_root() {
    // Trimming the dot off the text first would leave a dangling escape.
    assert_eq!(decode_name_labels(r"a\.").unwrap().0, vec!["a."]);
    assert_eq!(decode_name_labels("www.example.com.").unwrap().0.len(), 3);

    let zone = ZoneName::parse("example.com").unwrap();
    assert_eq!(
        OwnerName::parse_in_zone(r"a\.", &zone).unwrap().labels(),
        ["a."]
    );
}

/// Verify that `decode` rejects malformed escapes.
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

/// Verify that lookup name canonicalizes spelling and case.
#[test]
fn lookup_name_canonicalizes_spelling_and_case() {
    // Two spellings of one name must reach the database as one string: the
    // record filter compares them as text.
    assert_eq!(
        to_lookup_name(r"A\046B.Example.COM.").unwrap(),
        r"a\046b.example.com"
    );
    assert_eq!(
        to_lookup_name(r"a\.b.example.com").unwrap(),
        r"a\046b.example.com"
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

/// Verify that containment compares whole labels.
#[test]
fn containment_compares_whole_labels() {
    let labels = |name: &str| decode_name_labels(name).unwrap().0;

    assert!(is_label_suffix(
        &labels("www.example.com"),
        &labels("example.com")
    ));
    assert!(is_label_suffix(
        &labels("example.com"),
        &labels("example.com")
    ));
    assert!(!is_label_suffix(
        &labels("aexample.com"),
        &labels("example.com")
    ));
    assert!(!is_label_suffix(
        &labels("example.com"),
        &labels("www.example.com")
    ));

    // [evil.example, com] is one label short of being inside example.com; a
    // text suffix test would say it is.
    assert!(!is_label_suffix(
        &labels(r"evil\.example.com"),
        &labels("example.com")
    ));
}

/// Verify that owner name parse reduces input to the stored form.
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

/// Verify that owner name parse strips the zone suffix once.
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

/// Verify that owner name keeps an escaped dot as label data.
#[test]
fn owner_name_keeps_an_escaped_dot_as_label_data() {
    let zone = ZoneName::parse("example.com").unwrap();

    let owner = OwnerName::parse_in_zone(r"host\.name.example.com.", &zone).unwrap();
    assert_eq!(owner.labels(), ["host.name"]);
    assert_eq!(owner.to_stored(), r"host\046name");
    assert_eq!(owner.to_fqdn(&zone), r"host\046name.example.com.");

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

/// Verify that a rendered dot is always a label boundary.
#[test]
fn a_rendered_dot_is_always_a_label_boundary() {
    // SQL matches a grant's subtree as `LIKE '%.sub'`, so the single label
    // `a.sub` must not render to text ending in `.sub`; `[a\, sub]` may.
    assert_eq!(OwnerName::from_row(r"a\.sub").to_stored(), r"a\046sub");
    assert_eq!(OwnerName::from_row(r"a\\.sub").to_stored(), r"a\\.sub");
}

/// Verify that `escape_non_ascii` renders free text as name columns hold it.
#[test]
fn escape_non_ascii_renders_free_text_as_name_columns_hold_it() {
    assert_eq!(
        escape_non_ascii("caf\u{e9}.example"),
        r"caf\195\169.example"
    );
    // ASCII text is left as typed, dots and escapes included: a search term
    // is not a name, so nothing in it is a label to render.
    assert_eq!(escape_non_ascii(r"a\.b_c%"), r"a\.b_c%");
}

/// Verify that a non-ASCII label renders in decimal escapes.
#[test]
fn a_non_ascii_label_renders_in_decimal_escapes() {
    let zone = ZoneName::parse("example.com").unwrap();

    // Printable ASCII, as BIND writes it, so an ASCII column compares the row
    // bytewise; the escapes decode back to the same label.
    let owner = OwnerName::parse_in_zone("café", &zone).unwrap();
    assert_eq!(owner.to_stored(), r"caf\195\169");
    assert_eq!(OwnerName::from_row(&owner.to_stored()), owner);
}

/// Verify that owner name parse enforces the length limit on both paths.
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

/// Verify that owner name parse rejects names outside the zone.
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

/// Verify that owner name parse absolute never qualifies a foreign name.
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

/// Verify that owner name equality and hashing fold case.
#[test]
fn owner_name_equality_and_hashing_fold_case() {
    use std::collections::HashSet;

    assert_eq!(OwnerName::from_row("WWW"), OwnerName::from_row("www"));
    assert!(OwnerName::from_row("").is_apex());

    let mut seen = HashSet::new();
    seen.insert(OwnerName::from_row("WWW"));
    assert!(seen.contains(&OwnerName::from_row("www")));
}

/// Verify that owner name to fqdn resolves within its zone.
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

/// Verify that owner name is same or under compares labels.
#[test]
fn owner_name_is_same_or_under_compares_labels() {
    let sub = OwnerName::from_row("sub");

    assert!(OwnerName::from_row("a.sub").is_same_or_under(&sub));
    assert!(sub.is_same_or_under(&sub));
    assert!(!OwnerName::from_row("xsub").is_same_or_under(&sub));
    // `a\.sub` is the single label `a.sub`, so it is not under `sub`.
    assert!(!OwnerName::from_row(r"a\.sub").is_same_or_under(&sub));
}

/// Verify that zone name parse normalizes case and the trailing dot.
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

/// Verify that zone name parse rejects malformed names.
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

/// Verify that every accepted owner name survives storage and wire encoding unchanged.
///
/// The apex sentinel and decimal whitespace escapes exercise the two encodings this invariant
/// depends on.
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

/// Verify that both owner constructors accept the same labels, differing only in their
/// treatment of names outside the zone.
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

/// Verify that owner names can reach the 255-octet wire limit of RFC 1035, Section 2.3.4.
///
/// The 253-character presentation limit must not be applied to wire bytes.
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

/// Verify that owner names escape master-file metacharacters.
///
/// Unescaped metacharacters would terminate the owner field or comment out the rest of the
/// record.
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

/// Verify that the longest escaped owner name fits the database column.
///
/// The wire limit bounds decoded labels, so the schema must also allow for their presentation
/// escapes.
#[test]
fn worst_case_stored_form_fits_the_schema_column_width() {
    const SCHEMA_COLUMN_WIDTH: usize = 1024;
    let zone = ZoneName::parse("e.co").unwrap();

    // Every dot renders as four characters; four labels is the split that
    // maximizes the rendering under the 63-byte label cap and the wire budget.
    let labels = [
        r"\.".repeat(63),
        r"\.".repeat(63),
        r"\.".repeat(63),
        r"\.".repeat(56),
    ];
    let decoded: usize = labels.iter().map(|label| label.len() / 2).sum();

    let owner = OwnerName::parse_in_zone(&labels.join("."), &zone)
        .expect("the largest name the wire limit admits inside this zone");
    let stored = owner.to_stored();

    assert_eq!(stored.len(), decoded * 4 + labels.len() - 1);
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

/// Verify that `encode_name` produces length prefixed labels.
#[test]
fn encode_name_produces_length_prefixed_labels() {
    assert_eq!(
        encode_name("example.com.").unwrap(),
        [&[7u8][..], b"example", &[3], b"com", &[0]].concat()
    );
}

/// Verify that encoding keeps an escaped dot inside one label (RFC 1035, Section 5.1).
///
/// SOA mailboxes with a dotted local part rely on this label boundary.
#[test]
fn encode_name_keeps_escaped_dots_in_one_label() {
    assert_eq!(
        encode_name(r"admin\.dns.example.com.").unwrap(),
        [
            &[9u8][..],
            b"admin.dns",
            &[7],
            b"example",
            &[3],
            b"com",
            &[0]
        ]
        .concat()
    );
}

/// Verify that `encode_name` maps empty and root to the root name.
#[test]
fn encode_name_maps_empty_and_root_to_the_root_name() {
    assert_eq!(encode_name("").unwrap(), vec![0]);
    assert_eq!(encode_name(".").unwrap(), vec![0]);
}

/// Verify that owner to wire matches the encoded fqdn.
#[test]
fn owner_to_wire_matches_the_encoded_fqdn() {
    let zone = zone();
    let owner = OwnerName::parse_in_zone(r"api\.v2.www", &zone).unwrap();
    assert_eq!(
        owner.to_wire(&zone).unwrap(),
        encode_name(&owner.to_fqdn(&zone)).unwrap()
    );
}

/// Verify that zone to wire matches the encoded fqdn.
#[test]
fn zone_to_wire_matches_the_encoded_fqdn() {
    let zone = zone();
    assert_eq!(
        zone.to_wire().unwrap(),
        encode_name(&zone.to_fqdn()).unwrap()
    );
}
