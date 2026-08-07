use super::{TxtContent, TxtRdata};

#[test]
fn raw_txt_rdata_encode_decode() {
    let rdata = [2, b'a', b'b', 1, b'c'];
    let stored = TxtRdata::from_rdata(&rdata).into_encoded();

    assert_eq!(
        TxtRdata::from_encoded(&stored).map(TxtRdata::into_rdata),
        Some(rdata.to_vec())
    );
}

#[test]
fn txt_segments_encode_reversible() {
    let rdata = TxtRdata::from_segments(["a", "bc"]).unwrap();

    assert_eq!(
        rdata.to_content(),
        Some(TxtContent::Segments(vec![
            "a".to_string(),
            "bc".to_string()
        ]))
    );
}

#[test]
fn txt_segments_reject_empty_lists() {
    assert_eq!(
        TxtRdata::from_segments(std::iter::empty()).unwrap_err(),
        "TXT record must contain at least one character-string"
    );
}

#[test]
fn txt_value_rejects_empty_rdata() {
    assert_eq!(TxtRdata::from_rdata(&[]).to_content(), None);
}

#[test]
fn txt_segments_allow_single_empty_segment() {
    let rdata = TxtRdata::from_segments([""]).unwrap();

    assert_eq!(rdata.clone().into_rdata(), vec![0]);
    assert_eq!(rdata.to_content(), Some(TxtContent::Single(String::new())));
}

#[test]
fn txt_string_splits_long_values() {
    let rdata = TxtRdata::from_string(&"a".repeat(300));

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

#[test]
fn txt_string_splits_on_utf8_boundaries() {
    let rdata = TxtRdata::from_string(&format!("{}{}", "a".repeat(254), "é"));

    assert_eq!(
        rdata.to_content(),
        Some(TxtContent::Segments(vec!["a".repeat(254), "é".to_string()]))
    );
}

#[test]
fn from_encoded_ignores_invalid_prefix() {
    assert!(TxtRdata::from_encoded("bindizr:txt-rdata:v1:A2Fi").is_none());
}

#[test]
fn from_presentation_reads_quoted_segments() {
    assert_eq!(
        TxtRdata::from_presentation(r#""heritage=external-dns,external-dns/owner=default""#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Single(
            "heritage=external-dns,external-dns/owner=default".to_string()
        ))
    );
    assert_eq!(
        TxtRdata::from_presentation(r#""first" "second""#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Segments(vec![
            "first".to_string(),
            "second".to_string()
        ]))
    );
    assert_eq!(
        TxtRdata::from_presentation(r#""""#).unwrap().to_content(),
        Some(TxtContent::Single(String::new()))
    );
}

#[test]
fn from_presentation_unescapes_quotes_backslashes_and_ddd() {
    assert_eq!(
        TxtRdata::from_presentation(r#""a\"b\\c\032d""#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Single(r#"a"b\c d"#.to_string()))
    );
}

#[test]
fn from_presentation_treats_bare_value_as_content() {
    assert_eq!(
        TxtRdata::from_presentation("v=spf1 -all")
            .unwrap()
            .to_content(),
        Some(TxtContent::Single("v=spf1 -all".to_string()))
    );
}

#[test]
fn from_presentation_keeps_bare_value_whitespace() {
    assert_eq!(
        TxtRdata::from_presentation(" padded ")
            .unwrap()
            .to_content(),
        Some(TxtContent::Single(" padded ".to_string()))
    );
    assert_eq!(
        TxtRdata::from_presentation("   ").unwrap().to_content(),
        Some(TxtContent::Single("   ".to_string()))
    );
    // Whitespace around a quoted value is formatting, not content.
    assert_eq!(
        TxtRdata::from_presentation(r#"  "padded"  "#)
            .unwrap()
            .to_content(),
        Some(TxtContent::Single("padded".to_string()))
    );
}

#[test]
fn from_presentation_splits_long_bare_value() {
    assert_eq!(
        TxtRdata::from_presentation(&"a".repeat(300))
            .unwrap()
            .to_content(),
        Some(TxtContent::Segments(vec!["a".repeat(255), "a".repeat(45)]))
    );
}

#[test]
fn from_presentation_rejects_malformed_values() {
    assert!(TxtRdata::from_presentation("").is_err());
    assert!(TxtRdata::from_presentation(r#""unterminated"#).is_err());
    assert!(TxtRdata::from_presentation(r#""a"x"b""#).is_err());
    assert!(TxtRdata::from_presentation(r#""bad\9""#).is_err());
    assert!(TxtRdata::from_presentation(r#""bad\999""#).is_err());
    assert!(TxtRdata::from_presentation(&format!("\"{}\"", "a".repeat(256))).is_err());
}

#[test]
fn to_presentation_round_trips_ownership_records() {
    let ownership = r#""heritage=external-dns,external-dns/owner=default,external-dns/resource=ingress/default/app""#;
    assert_eq!(
        TxtRdata::from_presentation(ownership)
            .unwrap()
            .to_presentation(),
        ownership
    );
    // A bare value canonicalizes to its quoted form and is then stable.
    let canonical = TxtRdata::from_presentation("v=spf1 -all")
        .unwrap()
        .to_presentation();
    assert_eq!(canonical, r#""v=spf1 -all""#);
    assert_eq!(
        TxtRdata::from_presentation(&canonical)
            .unwrap()
            .to_presentation(),
        canonical
    );
}
