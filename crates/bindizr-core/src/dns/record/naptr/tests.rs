use super::*;
use crate::dns::record::{ParseRecordValueError, to_quoted_charstr};

/// Reject invalid flags with either replacement form.
#[test]
fn naptr_flags_reject_non_alphanumeric_characters() {
    let invalid = (0..=127u8)
        .filter(|byte| !byte.is_ascii_alphanumeric())
        .map(|byte| String::from(char::from(byte)))
        .chain(["é".to_string(), "한".to_string(), "９".to_string()]);
    for flags in invalid {
        for replacement in [".", "next.example."] {
            let text = format!(
                "1 1 {} \"app\" \"\" {replacement}",
                to_quoted_charstr(flags.as_bytes()),
            );
            let parsed = NaptrRecordValue::parse(&text).unwrap();
            assert!(
                matches!(parsed.validate(), Err(ParseRecordValueError::NaptrFlags)),
                "{text} was accepted"
            );
            let wire =
                NaptrRecordValue::from_wire(1, 1, flags.as_bytes(), b"app", b"", replacement)
                    .unwrap();
            assert!(
                matches!(wire.validate(), Err(ParseRecordValueError::NaptrFlags)),
                "wire flags {flags:?} were accepted"
            );
        }
    }
}

/// Preserve empty and application-defined flags.
#[test]
fn naptr_flags_allow_empty_and_application_defined_values() {
    for flags in [
        String::new(),
        "uSaPz9".to_string(),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_string(),
        "z".repeat(255),
    ] {
        let text = format!("1 1 \"{flags}\" \"app\" \"\" next.example.");
        let parsed = NaptrRecordValue::parse(&text).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.canonical(), text);
        let wire =
            NaptrRecordValue::from_wire(1, 1, flags.as_bytes(), b"app", b"", "next.example.")
                .unwrap();
        wire.validate().unwrap();
        assert_eq!(wire.canonical(), text);
    }
    let escaped = NaptrRecordValue::parse(r#"1 1 "\117\090\057" "app" "" ."#).unwrap();
    escaped.validate().unwrap();
    assert_eq!(escaped.canonical(), r#"1 1 "uZ9" "app" "" ."#);
}

/// Verify NAPTR parsing and replacement-name canonicalization.
#[test]
fn parses_the_presentation_form_and_canonicalizes_the_replacement() {
    let parsed =
        NaptrRecordValue::parse("100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.Example.COM.").unwrap();

    assert_eq!(
        parsed.canonical(),
        "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."
    );
}

/// Verify that a root replacement ends the rewrite chain.
#[test]
fn a_root_replacement_ends_the_rewrite_chain() {
    let value = "200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .";
    let parsed = NaptrRecordValue::parse(value).unwrap();

    parsed.validate().unwrap();
    assert_eq!(parsed.canonical(), value);
}

/// Verify conversion of NAPTR wire data into its stored form.
#[test]
fn reads_a_wire_record_back_into_the_stored_form() {
    assert_eq!(
        NaptrRecordValue::from_wire(100, 10, b"S", b"SIP+D2U", b"", "_sip._udp.Example.COM")
            .unwrap()
            .canonical(),
        "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."
    );
    assert_eq!(
        NaptrRecordValue::from_wire(200, 20, b"u", b"E2U+tel", b"!^.*$!tel:+1!", ".")
            .unwrap()
            .canonical(),
        "200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" ."
    );
}

/// Verify that a regexp may carry quotes and escapes.
#[test]
fn a_regexp_may_carry_quotes_and_escapes() {
    let parsed = NaptrRecordValue::parse(r#"1 1 "u" "E2U+sip" "!\"a\"!sip:b!" ."#).unwrap();

    assert_eq!(parsed.canonical(), r#"1 1 "u" "E2U+sip" "!\"a\"!sip:b!" ."#);
}

/// Verify that a regexp BIND refuses fails validation, not just parsing.
#[test]
fn a_regexp_bind_refuses_fails_validation() {
    let parsed = NaptrRecordValue::parse("10 10 \"u\" \"E2U+sip\" \"garbage\" .").unwrap();

    let err = parsed.validate().unwrap_err();
    assert!(
        matches!(err, ParseRecordValueError::NaptrRegexp(_)),
        "{err}"
    );
}

/// Verify that a regexp and a replacement name together are rejected.
#[test]
fn a_regexp_and_a_replacement_name_together_are_rejected() {
    // RFC 3403, Section 4.1 makes the two mutually exclusive.
    let parsed =
        NaptrRecordValue::parse("10 10 \"u\" \"E2U+sip\" \"!^.*$!sip:x!\" next.example.").unwrap();

    assert!(parsed.validate().is_err());
}

/// Verify rejection of NAPTR values with missing fields.
#[test]
fn rejects_a_value_missing_a_field() {
    for value in [
        "100 10 \"S\" \"SIP+D2U\" \"\"",
        "100 \"S\" \"SIP+D2U\" \"\" .",
        "100 10 S \"SIP+D2U\" \"\" .",
        "100 10 \"S\" \"SIP+D2U\" \"\" a.example.com b.example.com",
    ] {
        assert!(
            NaptrRecordValue::parse(value).is_err(),
            "{value} was accepted"
        );
    }
}
