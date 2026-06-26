use super::{decode_raw_txt_rdata, encode_raw_txt_rdata};

#[test]
fn raw_txt_rdata_encode_decode() {
    let rdata = [2, b'a', b'b', 1, b'c'];
    let encoded = encode_raw_txt_rdata(&rdata);

    assert_eq!(decode_raw_txt_rdata(&encoded), Some(rdata.to_vec()));
}

#[test]
fn txt_segments_encode_reversible_json() {
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
