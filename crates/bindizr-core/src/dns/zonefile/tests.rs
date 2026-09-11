//! Zone file parsing: TTL units, the slots the pre-pass may touch, and the
//! line numbers errors report.

use super::*;

#[test]
fn txt_rejects_non_utf8_octets() {
    // `\255\254` decode to bytes 0xFF 0xFE, which are not valid UTF-8.
    let parsed = parse_zone_file("weird IN TXT \"\\255\\254\"\n", "example.com", 3600);
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

#[test]
fn parse_error_names_the_line_of_the_submitted_text() {
    // An unknown rtype is caught where it sits; an rdata error is reported
    // at the end of the entry, which would blur what this pins down.
    let parsed = parse_zone_file(
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

#[test]
fn txt_utf8_multi_segment_parses_as_segments() {
    let parsed = parse_zone_file("multi IN TXT \"foo\" \"bar\"\n", "example.com", 3600);
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

#[test]
fn a_ttl_written_with_units_reaches_the_parsed_record() {
    // The slot rules are the rewrite's own tests; this is the round trip.
    let parsed = parse_zone_file("$TTL 1h\nwww 2d IN A 192.0.2.1\n", "example.com", 300);

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(parsed.rrs.len(), 1);
    assert_eq!(parsed.rrs[0].ttl, 172_800);
}
