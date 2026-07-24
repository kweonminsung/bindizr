use domain::{
    base::{
        Message,
        iana::{Opcode, Rcode, TsigRcode},
    },
    rdata::tsig::Tsig,
};

use super::{
    auth,
    auth::tests::{encode_name, encode_u48, hmac_sign, now_secs, signed_update, test_key},
    build_response,
    parser::tests::minimal_update_with_ztype,
};
use crate::{model::tsig_key::TsigAlgorithm, protocol::CLASS_ANY};

#[test]
fn build_response_echoes_request_header_and_question() {
    let query = minimal_update_with_ztype(6);

    let response = build_response(&query, Rcode::REFUSED, None, 300).unwrap();

    let msg = Message::from_octets(&response[..]).unwrap();
    let header = msg.header();
    assert_eq!(header.id(), 0x1234);
    assert!(header.qr());
    assert_eq!(header.opcode(), Opcode::UPDATE);
    assert_eq!(header.rcode(), Rcode::REFUSED);
    assert_eq!(msg.header_counts().qdcount(), 1);
    assert_eq!(msg.header_counts().arcount(), 0);
}

#[test]
fn build_response_signs_with_request_mac_chain() {
    let query = signed_update(TsigAlgorithm::HmacSha256, now_secs());
    let key = auth::to_domain_key(&test_key(TsigAlgorithm::HmacSha256)).unwrap();
    let signer = auth::validate_tsig(&query, Some(key)).unwrap();

    let response = build_response(&query, Rcode::NOERROR, Some(signer), 300).unwrap();

    let msg = Message::from_octets(&response[..]).unwrap();
    assert_eq!(msg.header().rcode(), Rcode::NOERROR);
    let record = msg
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let data = record.data();
    assert_eq!(data.error(), TsigRcode::NOERROR);
    assert_eq!(data.fudge(), 300);

    // The request's MAC is the last rdata field before the trailing original
    // ID, error, and other-len (2 bytes each).
    let request_mac = query[query.len() - 6 - 32..query.len() - 6].to_vec();

    // The response without its TSIG RR (ARCOUNT still 0) is exactly the
    // unsigned build of the same request.
    let unsigned = build_response(&query, Rcode::NOERROR, None, 300).unwrap();

    // Recompute the response MAC per RFC 8945 §4.3.3: request MAC
    // (length-prefixed), the response without the TSIG RR, then the TSIG
    // variables.
    let mut digest = Vec::new();
    digest.extend_from_slice(&(request_mac.len() as u16).to_be_bytes());
    digest.extend_from_slice(&request_mac);
    digest.extend_from_slice(&unsigned);
    digest.extend_from_slice(&encode_name("update-key"));
    digest.extend_from_slice(&CLASS_ANY.to_be_bytes());
    digest.extend_from_slice(&0u32.to_be_bytes());
    digest.extend_from_slice(&encode_name("hmac-sha256"));
    digest.extend_from_slice(&encode_u48(u64::from(data.time_signed())));
    digest.extend_from_slice(&data.fudge().to_be_bytes());
    digest.extend_from_slice(&0u16.to_be_bytes()); // error
    digest.extend_from_slice(&0u16.to_be_bytes()); // other len

    let expected = hmac_sign(TsigAlgorithm::HmacSha256, &digest);
    assert_eq!(*data.mac(), &expected[..]);
}
