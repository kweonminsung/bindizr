use std::str::FromStr;

use bindizr_core::dns::message::Name;

use super::*;
use crate::dns_client::ds::tests::encode_name;

/// A NOTIFY response with `flags`, echoing a SOA question for `qname`.
fn notify_response(query_id: u16, flags: u16, qname: &str) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query_id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    encode_name(qname, &mut response);
    response.extend_from_slice(&6u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response
}

fn zone() -> Name<Vec<u8>> {
    Name::from_str("example.com").unwrap()
}

#[test]
fn validate_notify_response_accepts_matching_noerror_response() {
    // 0xa000 = QR set + opcode NOTIFY, NOERROR.
    let response = notify_response(1234, 0xa000, "example.com");

    assert!(validate_notify_response(1234, &zone(), &response).is_ok());
}

#[test]
fn validate_notify_response_rejects_id_mismatch() {
    let response = notify_response(1234, 0xa000, "example.com");

    let err = validate_notify_response(5678, &zone(), &response).unwrap_err();

    assert!(err.contains("ID mismatch"));
}

#[test]
fn validate_notify_response_rejects_error_rcode() {
    // 0xa005 adds RCODE 5 (REFUSED).
    let response = notify_response(1234, 0xa005, "example.com");

    let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

    assert!(err.contains("RCODE 5"));
}

#[test]
fn validate_notify_response_rejects_another_question() {
    let response = notify_response(1234, 0xa000, "other.com");

    let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

    assert!(err.contains("another question"), "{err}");
}
