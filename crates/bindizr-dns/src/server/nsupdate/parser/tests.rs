use super::{ParseError, parse_update_request};

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

fn set_arcount(message: &mut [u8], arcount: u16) {
    message[10..12].copy_from_slice(&arcount.to_be_bytes());
}

fn append_opt_rr(message: &mut Vec<u8>) {
    message.extend_from_slice(&[
        0x00, // Root owner name
        0x00, 0x29, // TYPE OPT
        0x04, 0xd0, // UDP payload size
        0x00, 0x00, 0x00, 0x00, // Extended RCODE, version, flags
        0x00, 0x00, // RDLEN
    ]);
}

fn append_tsig_rr(message: &mut Vec<u8>) {
    append_tsig_rr_with_owner(message, &[0x03, b'k', b'e', b'y', 0x00]);
}

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

#[test]
fn parse_update_request_rejects_non_soa_zone_type() {
    let message = minimal_update_with_ztype(1);
    let err = parse_update_request(&message).unwrap_err();
    assert!(matches!(err, ParseError::InvalidZoneSection));
}

#[test]
fn parse_update_request_accepts_soa_zone_type() {
    let message = minimal_update_with_ztype(6);
    let request = parse_update_request(&message).unwrap();
    assert_eq!(request.zone_name, "example.com.");
}

#[test]
fn parse_update_request_accepts_opt_additional_without_tsig() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_opt_rr(&mut message);

    let request = parse_update_request(&message).unwrap();
    assert!(request.tsig.is_none());
}

#[test]
fn parse_update_request_accepts_opt_before_tsig() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_opt_rr(&mut message);
    append_tsig_rr(&mut message);

    let request = parse_update_request(&message).unwrap();
    let tsig = request.tsig.unwrap();
    assert_eq!(tsig.name, "key.");
    assert_eq!(tsig.fudge, 300);
}

/// Dots inside a key-name label must survive into the presentation-form name
/// used for the key lookup.
#[test]
fn parse_update_request_preserves_tsig_owner_label_dots() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_tsig_rr_with_owner(
        &mut message,
        &[
            0x0c, b'K', b'e', b'y', b'.', b'W', b'i', b't', b'h', b'.', b'D', b'o', b't', 0x00,
        ],
    );

    let request = parse_update_request(&message).unwrap();
    let tsig = request.tsig.unwrap();
    assert_eq!(tsig.name, "Key.With.Dot.");
}

#[test]
fn parse_update_request_rejects_tsig_before_other_additional_rrs() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_tsig_rr(&mut message);
    append_opt_rr(&mut message);

    let err = parse_update_request(&message).unwrap_err();
    assert!(matches!(err, ParseError::InvalidTsig));
}
