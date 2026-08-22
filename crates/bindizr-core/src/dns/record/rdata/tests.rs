use super::*;
use crate::{
    dns::{name::encode_name, record::TxtRecordValue},
    model::record::RecordType,
};

#[test]
fn encode_a_rdata_is_the_address_octets() {
    // RFC 1035, Section 3.4.1.
    let encoded = EncodedRdata::from_columns(&RecordType::A, "192.0.2.1", None)
        .unwrap()
        .unwrap();
    assert_eq!(encoded.record_type, 1);
    assert_eq!(encoded.rdata.as_bytes(), [192, 0, 2, 1]);
}

#[test]
fn encode_aaaa_rdata_is_the_address_octets() {
    // RFC 3596, Section 2.2.
    let encoded = EncodedRdata::from_columns(&RecordType::AAAA, "2001:db8::1", None)
        .unwrap()
        .unwrap();
    assert_eq!(encoded.record_type, 28);
    assert_eq!(
        encoded.rdata.as_bytes(),
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
}

#[test]
fn encode_cname_rdata_is_the_target_name() {
    let encoded = EncodedRdata::from_columns(&RecordType::CNAME, "mail.example.com.", None)
        .unwrap()
        .unwrap();
    assert_eq!(encoded.record_type, 5);
    assert_eq!(
        encoded.rdata.as_bytes(),
        encode_name("mail.example.com.").unwrap()
    );
}

#[test]
fn encode_mx_rdata_is_preference_then_exchange() {
    // RFC 1035, Section 3.3.9; the preference lives in the priority column.
    let encoded = EncodedRdata::from_columns(&RecordType::MX, "mail.example.com", Some(10))
        .unwrap()
        .unwrap();
    assert_eq!(encoded.record_type, 15);
    let mut expected = vec![0, 10];
    expected.extend(encode_name("mail.example.com").unwrap());
    assert_eq!(encoded.rdata.as_bytes(), expected);
}

#[test]
fn encode_srv_rdata_is_priority_weight_port_target() {
    // RFC 2782; the value stores `weight port target`, priority its column.
    let encoded = EncodedRdata::from_columns(&RecordType::SRV, "5 5060 sip.example.com", Some(1))
        .unwrap()
        .unwrap();
    assert_eq!(encoded.record_type, 33);
    let mut expected = vec![0, 1, 0, 5, 0x13, 0xc4];
    expected.extend(encode_name("sip.example.com").unwrap());
    assert_eq!(encoded.rdata.as_bytes(), expected);
}

#[test]
fn encode_txt_rdata_wraps_a_plain_value_as_one_character_string() {
    let encoded = EncodedRdata::from_columns(&RecordType::TXT, "hello", None)
        .unwrap()
        .unwrap();
    assert_eq!(encoded.record_type, 16);
    assert_eq!(encoded.rdata.as_bytes(), [&[5u8][..], b"hello"].concat());
}

#[test]
fn encode_txt_rdata_passes_stored_raw_rdata_through() {
    let stored = TxtRecordValue::from_segments(["a", "b"])
        .unwrap()
        .into_encoded();
    let encoded = EncodedRdata::from_columns(&RecordType::TXT, &stored, None)
        .unwrap()
        .unwrap();
    assert_eq!(encoded.rdata.as_bytes(), [1, b'a', 1, b'b']);
}

#[test]
fn from_columns_skips_soa() {
    assert!(
        EncodedRdata::from_columns(&RecordType::SOA, "anything", None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn rdata_rejects_bytes_beyond_the_rdlength_limit() {
    assert!(Rdata::new(vec![0; u16::MAX as usize]).is_ok());
    assert!(Rdata::new(vec![0; u16::MAX as usize + 1]).is_err());
}

#[test]
fn rdata_round_trips_through_its_base64_row_form() {
    let rdata = Rdata::new(vec![0x00, 0x2b, 0xff, 0x01]).unwrap();
    assert_eq!(Rdata::from_base64(&rdata.to_base64()).unwrap(), rdata);
}

#[test]
fn rdata_round_trips_through_its_journal_form() {
    let rdata = Rdata::new(vec![0x00, 0x2b, 0xff, 0x01]).unwrap();
    let decoded = Rdata::from_journal_value(&rdata.to_journal_value()).expect("valid journal form");
    assert_eq!(decoded, rdata);
}

#[test]
fn from_journal_value_rejects_unprefixed_or_invalid_base64() {
    assert!(Rdata::from_journal_value("AAECAw==").is_none());
    assert!(Rdata::from_journal_value("bindizr:rdata:v1:not base64!").is_none());
}
