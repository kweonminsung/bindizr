//! Zone file parsing: TTL units, the slots the pre-pass may touch, and the
//! line numbers errors report.

use super::*;

/// Verify that TXT rejects non UTF8 octets.
#[test]
fn txt_rejects_non_utf8_octets() {
    // `\255\254` decode to bytes 0xFF 0xFE, which are not valid UTF-8.
    let parsed = ParsedZoneFile::parse("weird IN TXT \"\\255\\254\"\n", "example.com", 3600);
    assert!(
        parsed.errors.iter().any(|e| e.contains("not valid UTF-8")),
        "expected a UTF-8 error, got: {:?}",
        parsed.errors
    );
    assert!(
        !parsed
            .rrs
            .iter()
            .any(|rr| rr.record_type == RecordType::TXT),
        "the non-UTF-8 TXT record should not have been stored"
    );
}

/// Verify that parse error names the line of the submitted text.
#[test]
fn parse_error_names_the_line_of_the_submitted_text() {
    // An unknown rtype is caught where it sits; an rdata error is reported
    // at the end of the entry, which would blur what this pins down.
    let parsed = ParsedZoneFile::parse(
        "ok IN A 192.0.2.1\nbad !!! IN A 192.0.2.2\n",
        "example.com",
        3600,
    );
    assert!(
        parsed.errors.iter().any(|e| e.contains(": 2:")),
        "expected the error to name line 2, got: {:?}",
        parsed.errors
    );
}

/// Verify that TXT UTF8 multi segment parses as segments.
#[test]
fn txt_utf8_multi_segment_parses_as_segments() {
    let parsed = ParsedZoneFile::parse("multi IN TXT \"foo\" \"bar\"\n", "example.com", 3600);
    assert!(
        parsed.errors.is_empty(),
        "unexpected errors: {:?}",
        parsed.errors
    );
    let rr = parsed
        .rrs
        .iter()
        .find(|rr| rr.record_type == RecordType::TXT)
        .expect("a TXT record");
    match &rr.value {
        ZoneFileValue::CharacterStrings(segments) => assert_eq!(segments, &["foo", "bar"]),
        other => panic!("expected segments, got {other:?}"),
    }
}

/// Verify that a TTL written with a BIND unit suffix is refused on its line.
#[test]
fn a_ttl_written_with_units_is_refused() {
    // RFC 1035, Section 5.1 defines the TTL as a decimal integer; the suffix
    // is a BIND extension, and `named-compilezone` writes it back as seconds.
    let parsed = ParsedZoneFile::parse(
        "www IN A 192.0.2.1\nmail 1h IN A 192.0.2.2\n",
        "example.com",
        300,
    );

    assert_eq!(parsed.rrs.len(), 1);
    assert_eq!(parsed.errors.len(), 1, "{:?}", parsed.errors);
    assert!(
        parsed.errors[0].starts_with("failed to parse zone file: 2:"),
        "{}",
        parsed.errors[0]
    );
}

/// Verify zone-file parsing of NAPTR presentation data.
#[test]
fn reads_a_naptr_record_in_its_own_presentation_form() {
    // `domain` renders a root replacement as `..`, so the value comes from
    // the parsed fields rather than its display form.
    let parsed = ParsedZoneFile::parse(
        concat!(
            "tel IN NAPTR 200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .\n",
            "sip IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.Example.COM.\n",
        ),
        "example.com",
        300,
    );

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    let values: Vec<_> = parsed.rrs.iter().map(|rr| &rr.value).collect();
    assert_eq!(
        values,
        [
            &ZoneFileValue::Rdata("200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .".to_string()),
            &ZoneFileValue::Rdata(
                "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com.".to_string()
            ),
        ]
    );
}
