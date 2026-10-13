use domain::{
    base::{
        Message,
        iana::{Class, Opcode, OptRcode, Rcode, TsigRcode},
    },
    rdata::tsig::Tsig,
};

use super::{parser::tests::minimal_update_with_ztype, *};
use crate::{
    dns::tsig::{
        self,
        tests::{encode_name, encode_u48, hmac_sign, now_secs, signed_update, test_key},
    },
    model::tsig_key::TsigAlgorithm,
};

/// Verify that `build_response` echoes request header and question.
#[test]
fn build_response_echoes_request_header_and_question() {
    let query = minimal_update_with_ztype(6);

    let response = build_response(&query, OptRcode::REFUSED, None, None, 300).unwrap();

    let msg = Message::from_octets(&response[..]).unwrap();
    let header = msg.header();
    assert_eq!(header.id(), 0x1234);
    assert!(header.qr());
    assert_eq!(header.opcode(), Opcode::UPDATE);
    assert_eq!(header.rcode(), Rcode::REFUSED);
    assert_eq!(msg.header_counts().qdcount(), 1);
    assert_eq!(msg.header_counts().arcount(), 0);
}

/// Verify that `build_response` answers an EDNS request with an OPT
/// carrying the extended rcode (RFC 6891, Section 6.1.1).
#[test]
fn build_response_echoes_an_opt_with_the_extended_rcode() {
    let mut query = minimal_update_with_ztype(6);
    query[10..12].copy_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let response = build_response(&query, OptRcode::BADVERS, None, None, 300).unwrap();

    let msg = Message::from_octets(&response[..]).unwrap();
    let opt = msg.opt().expect("the OPT is echoed");
    assert_eq!(opt.rcode(msg.header()), OptRcode::BADVERS);
    assert_eq!(opt.udp_payload_size(), 1232);
}

/// Verify that `build_response` signs with request mac chain.
#[test]
fn build_response_signs_with_request_mac_chain() {
    let query = signed_update(TsigAlgorithm::HmacSha256, now_secs());
    let key = test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let signer = tsig::verify_tsig(&query, Some(key)).unwrap();

    let response = build_response(&query, OptRcode::NOERROR, None, Some(signer), 300).unwrap();

    let msg = Message::from_octets(&response[..]).unwrap();
    assert_eq!(msg.header().rcode(), Rcode::NOERROR);
    let tsig_record = msg
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let data = tsig_record.data();
    assert_eq!(data.error(), TsigRcode::NOERROR);
    assert_eq!(data.fudge(), 300);

    // The request's MAC is the last rdata field before the trailing original
    // ID, error, and other-len (2 bytes each).
    let request_mac = query[query.len() - 6 - 32..query.len() - 6].to_vec();

    // The unsigned build supplies the response before TSIG, including ARCOUNT.
    let unsigned = build_response(&query, OptRcode::NOERROR, None, None, 300).unwrap();

    // RFC 8945, Section 4.3.3: request MAC, unsigned response, TSIG variables.
    let mut digest = Vec::new();
    digest.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    digest.extend_from_slice(&request_mac);
    digest.extend_from_slice(&unsigned);
    digest.extend_from_slice(&encode_name("update-key"));
    digest.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    digest.extend_from_slice(&0u32.to_be_bytes());
    digest.extend_from_slice(&encode_name("hmac-sha256"));
    digest.extend_from_slice(&encode_u48(u64::from(data.time_signed())));
    digest.extend_from_slice(&data.fudge().to_be_bytes());
    digest.extend_from_slice(&0u16.to_be_bytes()); // error
    digest.extend_from_slice(&0u16.to_be_bytes()); // other len

    let expected = hmac_sign(TsigAlgorithm::HmacSha256, &digest);
    assert_eq!(*data.mac(), &expected[..]);
}
