use super::{decode_raw_txt_rdata, encode_raw_txt_rdata};

#[test]
fn raw_txt_rdata_encode_decode() {
    let rdata = [2, b'a', b'b', 1, b'c'];
    let encoded = encode_raw_txt_rdata(&rdata);

    assert_eq!(decode_raw_txt_rdata(&encoded), Some(rdata.to_vec()));
}

#[test]
fn txt_segments_encode_reversible() {
    let encoded = super::encode_txt_segments(["a", "bc"]).unwrap();

    assert_eq!(
        super::decode_raw_txt_value(&encoded),
        Some(super::DecodedTxtValue::Segments(vec![
            "a".to_string(),
            "bc".to_string()
        ]))
    );
}

#[test]
fn txt_segments_reject_empty_lists() {
    assert_eq!(
        super::encode_txt_segments(std::iter::empty()).unwrap_err(),
        "TXT record must contain at least one character-string"
    );
}

#[test]
fn txt_value_rejects_empty_rdata() {
    let encoded = encode_raw_txt_rdata(&[]);

    assert_eq!(super::decode_raw_txt_value(&encoded), None);
}

#[test]
fn txt_segments_allow_single_empty_segment() {
    let encoded = super::encode_txt_segments([""]).unwrap();

    assert_eq!(decode_raw_txt_rdata(&encoded), Some(vec![0]));
    assert_eq!(
        super::decode_raw_txt_value(&encoded),
        Some(super::DecodedTxtValue::String(String::new()))
    );
}

#[test]
fn txt_string_splits_long_values() {
    let value = "a".repeat(300);
    let encoded = super::encode_txt_string(&value);

    assert_eq!(
        decode_raw_txt_rdata(&encoded),
        Some({
            let mut rdata = Vec::new();
            rdata.push(255);
            rdata.extend(std::iter::repeat_n(b'a', 255));
            rdata.push(45);
            rdata.extend(std::iter::repeat_n(b'a', 45));
            rdata
        })
    );
    assert_eq!(
        super::decode_raw_txt_value(&encoded),
        Some(super::DecodedTxtValue::Segments(vec![
            "a".repeat(255),
            "a".repeat(45)
        ]))
    );
}

#[test]
fn txt_string_splits_on_utf8_boundaries() {
    let value = format!("{}{}", "a".repeat(254), "é");
    let encoded = super::encode_txt_string(&value);

    assert_eq!(
        super::decode_raw_txt_value(&encoded),
        Some(super::DecodedTxtValue::Segments(vec![
            "a".repeat(254),
            "é".to_string()
        ]))
    );
}

#[test]
fn raw_txt_rdata_ignores_invalid_prefix() {
    assert_eq!(decode_raw_txt_rdata("bindizr:txt-rdata:v1:A2Fi"), None);
}

#[test]
fn parse_txt_presentation_reads_quoted_segments() {
    assert_eq!(
        super::parse_txt_presentation(r#""heritage=external-dns,external-dns/owner=default""#),
        Ok(vec![
            "heritage=external-dns,external-dns/owner=default".to_string()
        ])
    );
    assert_eq!(
        super::parse_txt_presentation(r#""first" "second""#),
        Ok(vec!["first".to_string(), "second".to_string()])
    );
    assert_eq!(
        super::parse_txt_presentation(r#""""#),
        Ok(vec![String::new()])
    );
}

#[test]
fn parse_txt_presentation_unescapes_quotes_backslashes_and_ddd() {
    assert_eq!(
        super::parse_txt_presentation(r#""a\"b\\c\032d""#),
        Ok(vec![r#"a"b\c d"#.to_string()])
    );
}

#[test]
fn parse_txt_presentation_treats_bare_value_as_content() {
    assert_eq!(
        super::parse_txt_presentation("v=spf1 -all"),
        Ok(vec!["v=spf1 -all".to_string()])
    );
}

#[test]
fn parse_txt_presentation_keeps_bare_value_whitespace() {
    assert_eq!(
        super::parse_txt_presentation(" padded "),
        Ok(vec![" padded ".to_string()])
    );
    assert_eq!(
        super::parse_txt_presentation("   "),
        Ok(vec!["   ".to_string()])
    );
    // Whitespace around a quoted value is formatting, not content.
    assert_eq!(
        super::parse_txt_presentation(r#"  "padded"  "#),
        Ok(vec!["padded".to_string()])
    );
}

#[test]
fn parse_txt_presentation_splits_long_bare_value() {
    let value = "a".repeat(300);
    assert_eq!(
        super::parse_txt_presentation(&value),
        Ok(vec!["a".repeat(255), "a".repeat(45)])
    );
}

#[test]
fn parse_txt_presentation_rejects_malformed_values() {
    assert!(super::parse_txt_presentation("").is_err());
    assert!(super::parse_txt_presentation(r#""unterminated"#).is_err());
    assert!(super::parse_txt_presentation(r#""a"x"b""#).is_err());
    assert!(super::parse_txt_presentation(r#""bad\9""#).is_err());
    assert!(super::parse_txt_presentation(r#""bad\999""#).is_err());
    assert!(super::parse_txt_presentation(&format!("\"{}\"", "a".repeat(256))).is_err());
}

#[test]
fn canonical_txt_presentation_round_trips_ownership_records() {
    let ownership = r#""heritage=external-dns,external-dns/owner=default,external-dns/resource=ingress/default/app""#;
    assert_eq!(
        super::canonical_txt_presentation(ownership),
        Ok(ownership.to_string())
    );
    // A bare value canonicalizes to its quoted form and is then stable.
    let canonical = super::canonical_txt_presentation("v=spf1 -all").unwrap();
    assert_eq!(canonical, r#""v=spf1 -all""#);
    assert_eq!(super::canonical_txt_presentation(&canonical), Ok(canonical));
}
