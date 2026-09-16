use super::{ParseError, UpdateRequest, UpdateRr};
use crate::{
    dns::message::{Class, Rtype},
    model::record::RecordType,
};

/// Build a minimal UPDATE message with the requested zone type.
pub(crate) fn minimal_update_with_ztype(ztype: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&[
        0x12, 0x34, // ID
        0x28, 0x00, // Opcode UPDATE
        0x00, 0x01, // ZOCOUNT
        0x00, 0x00, // PRCOUNT
        0x00, 0x00, // UPCOUNT
        0x00, 0x00, // ADCOUNT
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
    ]);
    message.extend_from_slice(&ztype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message
}

/// Set the additional-record count in a test DNS header.
fn set_arcount(message: &mut [u8], arcount: u16) {
    message[10..12].copy_from_slice(&arcount.to_be_bytes());
}

/// Append an EDNS OPT record to the test message.
fn append_opt_rr(message: &mut Vec<u8>) {
    message.extend_from_slice(&[
        0x00, // Root owner name
        0x00, 0x29, // TYPE OPT
        0x04, 0xd0, // UDP payload size
        0x00, 0x00, 0x00, 0x00, // Extended RCODE, version, flags
        0x00, 0x00, // RDLEN
    ]);
}

/// Append a TSIG fixture with the default key name.
fn append_tsig_rr(message: &mut Vec<u8>) {
    append_tsig_rr_with_owner(message, &[0x03, b'k', b'e', b'y', 0x00]);
}

/// Append a TSIG fixture with the supplied owner name.
fn append_tsig_rr_with_owner(message: &mut Vec<u8>, owner: &[u8]) {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&[
        0x0b, b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'5', b'6', 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // Time signed
        0x01, 0x2c, // Fudge
        0x00, 0x00, // MAC size
        0x12, 0x34, // Original ID
        0x00, 0x00, // Error
        0x00, 0x00, // Other len
    ]);

    message.extend_from_slice(owner);
    message.extend_from_slice(&[
        0x00, 0xfa, // TYPE TSIG
        0x00, 0xff, // CLASS ANY
        0x00, 0x00, 0x00, 0x00, // TTL
    ]);
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);
}

/// Verify that `UpdateRequest::parse` rejects non SOA zone type.
#[test]
fn parse_update_request_rejects_non_soa_zone_type() {
    let message = minimal_update_with_ztype(1);
    let err = UpdateRequest::parse(&message).unwrap_err();
    assert!(matches!(err, ParseError::InvalidZoneSection));
}

/// Verify that `UpdateRequest::parse` accepts SOA zone type.
#[test]
fn parse_update_request_accepts_soa_zone_type() {
    let message = minimal_update_with_ztype(6);
    let request = UpdateRequest::parse(&message).unwrap();
    assert_eq!(request.zone_name, "example.com.");
}

/// Verify that `UpdateRequest::parse` accepts opt additional without TSIG.
#[test]
fn parse_update_request_accepts_opt_additional_without_tsig() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_opt_rr(&mut message);

    let request = UpdateRequest::parse(&message).unwrap();
    assert!(request.tsig.is_none());
}

/// Verify that `UpdateRequest::parse` accepts opt before TSIG.
#[test]
fn parse_update_request_accepts_opt_before_tsig() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_opt_rr(&mut message);
    append_tsig_rr(&mut message);

    let request = UpdateRequest::parse(&message).unwrap();
    let tsig = request.tsig.unwrap();
    assert_eq!(tsig.name, "key.");
    assert_eq!(tsig.fudge, 300);
}

/// Escaping keeps the one-label key name distinct from the multi-label name of
/// the same spelling, which decodes to different labels.
#[test]
fn parse_update_request_escapes_a_dot_inside_a_tsig_owner_label() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_tsig_rr_with_owner(
        &mut message,
        &[
            0x0c, b'K', b'e', b'y', b'.', b'W', b'i', b't', b'h', b'.', b'D', b'o', b't', 0x00,
        ],
    );

    let request = UpdateRequest::parse(&message).unwrap();
    assert_eq!(request.tsig.unwrap().name, r"Key\046With\046Dot.");
}

/// The wire carries one label holding a dot; rendering it unescaped would let
/// it read as two and land the update in a zone it is not in.
#[test]
fn parse_update_request_escapes_a_dot_inside_a_zone_label() {
    let mut message = Vec::new();
    message.extend_from_slice(&[
        0x12, 0x34, // ID
        0x28, 0x00, // Opcode UPDATE
        0x00, 0x01, // ZOCOUNT
        0x00, 0x00, // PRCOUNT
        0x00, 0x00, // UPCOUNT
        0x00, 0x00, // ADCOUNT
        0x0c, b'e', b'v', b'i', b'l', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', // One label
        0x03, b'c', b'o', b'm', 0x00,
    ]);
    message.extend_from_slice(&6u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());

    let request = UpdateRequest::parse(&message).unwrap();
    assert_eq!(request.zone_name, r"evil\046example.com.");
}

/// Verify that `UpdateRequest::parse` rejects TSIG before other additional rrs.
#[test]
fn parse_update_request_rejects_tsig_before_other_additional_rrs() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_tsig_rr(&mut message);
    append_opt_rr(&mut message);

    let err = UpdateRequest::parse(&message).unwrap_err();
    assert!(matches!(err, ParseError::InvalidTsig));
}

/// Verify that `to_record_value` preserves TXT character string boundaries.
#[test]
fn to_record_value_preserves_txt_character_string_boundaries() {
    let first = UpdateRr {
        name: "txt.example.com.".to_string(),
        rr_type: Rtype::TXT,
        class: Class::IN,
        ttl: 300,
        rdata: vec![2, b'a', b'b', 1, b'c'],
        rdata_start: 0,
    };
    let second = UpdateRr {
        name: "txt.example.com.".to_string(),
        rr_type: Rtype::TXT,
        class: Class::IN,
        ttl: 300,
        rdata: vec![1, b'a', 2, b'b', b'c'],
        rdata_start: 0,
    };

    let (_, first_value, _) = first.to_record_value(&first.rdata).unwrap();
    let (_, second_value, _) = second.to_record_value(&second.rdata).unwrap();

    assert_ne!(first_value, second_value);
    assert!(!RecordType::TXT.values_equal(&first_value, None, &second_value, None));
}

/// Verify that `to_record_value` follows compression pointer in name RDATA.
#[test]
fn to_record_value_follows_compression_pointer_in_name_rdata() {
    let mut message = vec![
        3, b'w', b'w', b'w', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let rdata_start = message.len();
    let pointer = [0xC0, 5]; // Points at the "example.com." bytes above
    message.extend_from_slice(&pointer);

    let rr = UpdateRr {
        name: "www.example.com.".to_string(),
        rr_type: Rtype::CNAME,
        class: Class::IN,
        ttl: 300,
        rdata: pointer.to_vec(),
        rdata_start,
    };

    let (record_type, value, priority) = rr.to_record_value(&message).unwrap();
    assert_eq!(record_type, RecordType::CNAME);
    assert_eq!(value, "example.com.");
    assert_eq!(priority, None);
}

/// Verify that `to_record_value` rejects non backward compression pointers.
#[test]
fn to_record_value_rejects_non_backward_compression_pointers() {
    let forward = [
        0xC0, 0x02, // Pointer to the root label after this pointer
        0x00,
    ];
    let self_referential = [
        0xC0, 0x00, // Pointer to itself
    ];

    for message in [&forward[..], &self_referential[..]] {
        let rr = update_rr(Rtype::CNAME, Class::IN, 300, message[..2].to_vec());
        let err = rr.to_record_value(message).unwrap_err();
        assert!(!err.is_empty());
    }
}

/// Verify that `to_record_value` rejects name RDATA with trailing bytes.
#[test]
fn to_record_value_rejects_name_rdata_with_trailing_bytes() {
    let message = [1, b'a', 0, 0];
    let rr = update_rr(Rtype::CNAME, Class::IN, 300, message.to_vec());
    let err = rr.to_record_value(&message).unwrap_err();
    assert!(!err.is_empty());
}

/// Verify rejection of empty TXT RDATA, which lacks the character-string required by RFC 1035,
/// Section 3.3.14.
#[test]
fn to_record_value_rejects_empty_txt_rdata() {
    let rr = update_rr(Rtype::TXT, Class::IN, 300, Vec::new());
    let err = rr.to_record_value(&[]).unwrap_err();
    assert!(!err.is_empty());
}

/// Verify that `to_record_value` rejects non UTF8 TXT character strings.
#[test]
fn to_record_value_rejects_non_utf8_txt_character_strings() {
    let rr = update_rr(Rtype::TXT, Class::IN, 300, vec![1, 0xFF]);
    let err = rr.to_record_value(&rr.rdata).unwrap_err();
    assert!(!err.is_empty());
}

/// Verify that `to_record_value` splits SRV priority into its own column.
#[test]
fn to_record_value_splits_srv_priority_into_its_own_column() {
    // priority 10, weight 20, port 5060, target sip.example.com.
    let mut rdata = vec![0, 10, 0, 20, 0x13, 0xC4];
    rdata.extend_from_slice(&[
        3, b's', b'i', b'p', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    let rr = update_rr(Rtype::SRV, Class::IN, 300, rdata.clone());

    let (record_type, value, priority) = rr.to_record_value(&rdata).unwrap();

    assert_eq!(record_type, RecordType::SRV);
    // The wire encoder reads back this 3-field form with the priority column.
    assert_eq!(value, "20 5060 sip.example.com.");
    assert_eq!(priority, Some(10));
}

/// Build a dynamic update record with the requested wire fields.
fn update_rr(rr_type: Rtype, class: Class, ttl: u32, rdata: Vec<u8>) -> UpdateRr {
    UpdateRr {
        name: "www.example.com.".to_string(),
        rr_type,
        class,
        ttl,
        rdata,
        rdata_start: 0,
    }
}
