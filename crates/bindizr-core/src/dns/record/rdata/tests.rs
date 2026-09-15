use super::*;
use crate::{
    dns::{name::encode_name, record::TxtRecordValue},
    model::record::RecordType,
};

/// Verify that encode a RDATA is the address octets.
#[test]
fn encode_a_rdata_is_the_address_octets() {
    // RFC 1035, Section 3.4.1.
    let encoded = EncodedRdata::from_columns(&RecordType::A, "192.0.2.1", None).unwrap();
    assert_eq!(encoded.record_type, 1);
    assert_eq!(encoded.rdata.as_bytes(), [192, 0, 2, 1]);
}

/// Verify that encode AAAA RDATA is the address octets.
#[test]
fn encode_aaaa_rdata_is_the_address_octets() {
    // RFC 3596, Section 2.2.
    let encoded = EncodedRdata::from_columns(&RecordType::AAAA, "2001:db8::1", None).unwrap();
    assert_eq!(encoded.record_type, 28);
    assert_eq!(
        encoded.rdata.as_bytes(),
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
}

/// Verify that encode CNAME RDATA is the target name.
#[test]
fn encode_cname_rdata_is_the_target_name() {
    let encoded =
        EncodedRdata::from_columns(&RecordType::CNAME, "mail.example.com.", None).unwrap();
    assert_eq!(encoded.record_type, 5);
    assert_eq!(
        encoded.rdata.as_bytes(),
        encode_name("mail.example.com.").unwrap()
    );
}

/// Verify that encode CAA RDATA is flags tag length tag then value.
#[test]
fn encode_caa_rdata_is_flags_tag_length_tag_then_value() {
    // RFC 8659, Section 4.1.
    let encoded =
        EncodedRdata::from_columns(&RecordType::CAA, "0 issue \"letsencrypt.org\"", None).unwrap();
    assert_eq!(encoded.record_type, 257);
    let mut expected = vec![0u8, 5];
    expected.extend_from_slice(b"issue");
    expected.extend_from_slice(b"letsencrypt.org");
    assert_eq!(encoded.rdata.as_bytes(), expected);
}

/// Verify that encode SSHFP RDATA is algorithm type then fingerprint.
#[test]
fn encode_sshfp_rdata_is_algorithm_type_then_fingerprint() {
    // RFC 4255, Section 3.1.
    let encoded = EncodedRdata::from_columns(&RecordType::SSHFP, "4 1 4B9B6B07", None).unwrap();
    assert_eq!(encoded.record_type, 44);
    assert_eq!(encoded.rdata.as_bytes(), [4, 1, 0x4B, 0x9B, 0x6B, 0x07]);
}

/// Verify that encode TLSA RDATA is usage selector matching then data.
#[test]
fn encode_tlsa_rdata_is_usage_selector_matching_then_data() {
    // RFC 6698, Section 2.1.
    let encoded = EncodedRdata::from_columns(&RecordType::TLSA, "3 1 0 4B9B6B07", None).unwrap();
    assert_eq!(encoded.record_type, 52);
    assert_eq!(encoded.rdata.as_bytes(), [3, 1, 0, 0x4B, 0x9B, 0x6B, 0x07]);
}

/// Verify that encode DS RDATA is tag algorithm digest type then digest.
#[test]
fn encode_ds_rdata_is_tag_algorithm_digest_type_then_digest() {
    // RFC 4034, Section 5.1.
    let encoded = EncodedRdata::from_columns(&RecordType::DS, "34217 13 2 4B9B6B07", None).unwrap();
    assert_eq!(encoded.record_type, 43);
    assert_eq!(
        encoded.rdata.as_bytes(),
        [0x85, 0xA9, 13, 2, 0x4B, 0x9B, 0x6B, 0x07]
    );
}

/// Verify that encode MX RDATA is preference then exchange.
#[test]
fn encode_mx_rdata_is_preference_then_exchange() {
    // RFC 1035, Section 3.3.9; the preference lives in the priority column.
    let encoded =
        EncodedRdata::from_columns(&RecordType::MX, "mail.example.com", Some(10)).unwrap();
    assert_eq!(encoded.record_type, 15);
    let mut expected = vec![0, 10];
    expected.extend(encode_name("mail.example.com").unwrap());
    assert_eq!(encoded.rdata.as_bytes(), expected);
}

/// Verify that encode SRV RDATA is priority weight port target.
#[test]
fn encode_srv_rdata_is_priority_weight_port_target() {
    // RFC 2782; the value stores `weight port target`, priority its column.
    let encoded =
        EncodedRdata::from_columns(&RecordType::SRV, "5 5060 sip.example.com", Some(1)).unwrap();
    assert_eq!(encoded.record_type, 33);
    let mut expected = vec![0, 1, 0, 5, 0x13, 0xc4];
    expected.extend(encode_name("sip.example.com").unwrap());
    assert_eq!(encoded.rdata.as_bytes(), expected);
}

/// Verify that encode TXT RDATA rejects a plain unquoted value.
#[test]
fn encode_txt_rdata_rejects_a_plain_unquoted_value() {
    assert!(EncodedRdata::from_columns(&RecordType::TXT, "hello", None).is_err());
}

/// Verify that encode TXT RDATA decodes the stored presentation form.
#[test]
fn encode_txt_rdata_decodes_the_stored_presentation_form() {
    let stored = TxtRecordValue::from_segments(["a", "b"])
        .unwrap()
        .to_presentation();
    let encoded = EncodedRdata::from_columns(&RecordType::TXT, &stored, None).unwrap();
    assert_eq!(encoded.rdata.as_bytes(), [1, b'a', 1, b'b']);
}

/// Verify that `rdata` rejects bytes beyond the rdlength limit.
#[test]
fn rdata_rejects_bytes_beyond_the_rdlength_limit() {
    assert!(Rdata::new(vec![0; u16::MAX as usize]).is_ok());
    assert!(Rdata::new(vec![0; u16::MAX as usize + 1]).is_err());
}

/// Verify that encode CNAME RDATA reads an escaped dot as label data.
#[test]
fn encode_cname_rdata_reads_an_escaped_dot_as_label_data() {
    // RFC 1035, Section 5.1: `a\.b` decodes to three octets in one label;
    // the escape is presentation syntax and the dot remains label data.
    let encoded =
        EncodedRdata::from_columns(&RecordType::CNAME, r"a\.b.example.com.", None).unwrap();

    assert_eq!(
        encoded.rdata.as_bytes(),
        [
            3, b'a', b'.', b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]
    );
}
