use super::{TxtContent, TxtRecordValue};

/// Verify that raw TXT RDATA round-trips through the row form.
#[test]
fn raw_txt_rdata_round_trips_through_the_row_form() {
    let rdata = [2, b'a', b'b', 1, b'c'];
    let stored = TxtRecordValue::from_rdata(&rdata)
        .unwrap()
        .to_presentation();

    assert_eq!(stored, r#""ab" "c""#);
    assert_eq!(
        TxtRecordValue::from_presentation(&stored).map(TxtRecordValue::into_rdata),
        Some(rdata.to_vec())
    );
}

/// Verify that TXT segment encoding is reversible.
#[test]
fn txt_segments_encode_reversible() {
    let rdata = TxtRecordValue::from_segments(["a", "bc"]).unwrap();

    assert_eq!(
        rdata.to_content(),
        Some(TxtContent::Segments(vec![
            "a".to_string(),
            "bc".to_string()
        ]))
    );
}

/// Verify that TXT segments reject empty lists.
#[test]
fn txt_segments_reject_empty_lists() {
    assert_eq!(
        TxtRecordValue::from_segments(std::iter::empty()).unwrap_err(),
        "TXT record must contain at least one character-string"
    );
}

/// Verify that `from_rdata` rejects empty or broken charstring chains.
#[test]
fn from_rdata_rejects_empty_or_broken_charstring_chains() {
    assert!(TxtRecordValue::from_rdata(&[]).is_err());
    assert!(TxtRecordValue::from_rdata(&[5, b'a']).is_err());
}

/// Verify that TXT segments allow single empty segment.
#[test]
fn txt_segments_allow_single_empty_segment() {
    let rdata = TxtRecordValue::from_segments([""]).unwrap();

    assert_eq!(rdata.clone().into_rdata(), vec![0]);
    assert_eq!(rdata.to_content(), Some(TxtContent::Single(String::new())));
}

/// Verify that TXT string splits long values.
#[test]
fn txt_string_splits_long_values() {
    let rdata = TxtRecordValue::from_string(&"a".repeat(300));

    assert_eq!(rdata.clone().into_rdata(), {
        let mut expected = Vec::new();
        expected.push(255);
        expected.extend(std::iter::repeat_n(b'a', 255));
        expected.push(45);
        expected.extend(std::iter::repeat_n(b'a', 45));
        expected
    });
    assert_eq!(
        rdata.to_content(),
        Some(TxtContent::Segments(vec!["a".repeat(255), "a".repeat(45)]))
    );
}

/// Verify that TXT string splits on UTF8 boundaries.
#[test]
fn txt_string_splits_on_utf8_boundaries() {
    let rdata = TxtRecordValue::from_string(&format!("{}{}", "a".repeat(254), "é"));

    assert_eq!(
        rdata.to_content(),
        Some(TxtContent::Segments(vec!["a".repeat(254), "é".to_string()]))
    );
}

/// Verify that `from_presentation` rejects unquoted values.
#[test]
fn from_presentation_rejects_unquoted_values() {
    assert!(TxtRecordValue::from_presentation("v=spf1 -all").is_none());
    assert!(TxtRecordValue::from_presentation("bindizr:txt-rdata:v1:A2Fi").is_none());
}

/// Verify that `parse` reads quoted segments.
#[test]
fn parse_reads_quoted_segments() {
    assert_eq!(
        TxtRecordValue::parse(r#""heritage=external-dns,external-dns/owner=default""#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Single(
            "heritage=external-dns,external-dns/owner=default".to_string()
        ))
    );
    assert_eq!(
        TxtRecordValue::parse(r#""first" "second""#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Segments(vec![
            "first".to_string(),
            "second".to_string()
        ]))
    );
    assert_eq!(
        TxtRecordValue::parse(r#""""#).unwrap().to_content(),
        Some(TxtContent::Single(String::new()))
    );
}

/// Verify that `parse` unescapes quotes backslashes and ddd.
#[test]
fn parse_unescapes_quotes_backslashes_and_ddd() {
    assert_eq!(
        TxtRecordValue::parse(r#""a\"b\\c\032d""#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Single(r#"a"b\c d"#.to_string()))
    );
}

/// Verify that `parse` treats bare value as content.
#[test]
fn parse_treats_bare_value_as_content() {
    assert_eq!(
        TxtRecordValue::parse("v=spf1 -all").unwrap().to_content(),
        Some(TxtContent::Single("v=spf1 -all".to_string()))
    );
}

/// Verify that `parse` keeps bare value whitespace.
#[test]
fn parse_keeps_bare_value_whitespace() {
    assert_eq!(
        TxtRecordValue::parse(" padded ").unwrap().to_content(),
        Some(TxtContent::Single(" padded ".to_string()))
    );
    assert_eq!(
        TxtRecordValue::parse("   ").unwrap().to_content(),
        Some(TxtContent::Single("   ".to_string()))
    );
    // Whitespace around a quoted value is formatting, not content.
    assert_eq!(
        TxtRecordValue::parse(r#"  "padded"  "#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Single("padded".to_string()))
    );
}

/// Verify that `parse` splits long bare value.
#[test]
fn parse_splits_long_bare_value() {
    assert_eq!(
        TxtRecordValue::parse(&"a".repeat(300))
            .unwrap()
            .to_content(),
        Some(TxtContent::Segments(vec!["a".repeat(255), "a".repeat(45)]))
    );
}

/// Verify that `parse` rejects malformed values.
#[test]
fn parse_rejects_malformed_values() {
    assert!(TxtRecordValue::parse("").is_err());
    assert!(TxtRecordValue::parse(r#""unterminated"#).is_err());
    assert!(TxtRecordValue::parse(r#""a"x"b""#).is_err());
    assert!(TxtRecordValue::parse(r#""bad\9""#).is_err());
    assert!(TxtRecordValue::parse(r#""bad\999""#).is_err());
    assert!(TxtRecordValue::parse(&format!("\"{}\"", "a".repeat(256))).is_err());
}

/// Verify that `to_presentation` round-trips ownership records.
#[test]
fn to_presentation_round_trips_ownership_records() {
    assert_eq!(
        TxtRecordValue::from_string("v=spf1 \"x\\y\"").to_presentation(),
        "\"v=spf1 \\\"x\\\\y\\\"\""
    );
    // Control bytes are escaped as \DDD per RFC 1035, Section 5.1.
    assert_eq!(
        TxtRecordValue::from_string("a\u{1}b").to_presentation(),
        "\"a\\001b\""
    );

    let ownership = r#""heritage=external-dns,external-dns/owner=default,external-dns/resource=ingress/default/app""#;
    assert_eq!(
        TxtRecordValue::parse(ownership).unwrap().to_presentation(),
        ownership
    );
    // A bare value canonicalizes to its quoted form and is then stable.
    let canonical = TxtRecordValue::parse("v=spf1 -all")
        .unwrap()
        .to_presentation();
    assert_eq!(canonical, r#""v=spf1 -all""#);
    assert_eq!(
        TxtRecordValue::parse(&canonical).unwrap().to_presentation(),
        canonical
    );
}

/// Verify that `validate` rejects data that cannot fit one DNS message.
#[test]
fn validate_rejects_data_that_cannot_fit_one_dns_message() {
    let segment = "a".repeat(255);
    let value = TxtRecordValue::from_segments(vec![segment.as_str(); 256]).unwrap();
    assert!(value.validate().is_err());
    assert!(
        TxtRecordValue::from_segments(vec![segment.as_str(); 4])
            .unwrap()
            .validate()
            .is_ok()
    );
}
