use std::str::FromStr;

use bindizr_core::dns::message::Name;

use super::extract_soa_serial;
use crate::dns_client::ds::tests::encode_name;

fn zone() -> Name<Vec<u8>> {
    Name::from_str("example.com").unwrap()
}

fn build_soa_response(
    query_id: u16,
    flags: u16,
    qname: &str,
    with_answer: bool,
    serial: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&query_id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&(u16::from(with_answer)).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    encode_name(qname, &mut buf);
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    if with_answer {
        encode_name(qname, &mut buf);
        buf.extend_from_slice(&6u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&3600u32.to_be_bytes());

        let mut rdata = Vec::new();
        encode_name("ns1.example.com", &mut rdata);
        encode_name("admin.example.com", &mut rdata);
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&7200u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&604800u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());

        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }

    buf
}

#[test]
fn extract_soa_serial_reads_the_answer_serial() {
    // 0x8400 = QR + AA, NOERROR.
    let response = build_soa_response(42, 0x8400, "example.com", true, 2026);
    assert_eq!(extract_soa_serial(42, &zone(), &response).unwrap(), 2026);
}

#[test]
fn extract_soa_serial_rejects_id_mismatch() {
    let response = build_soa_response(42, 0x8400, "example.com", true, 2026);
    assert!(
        extract_soa_serial(7, &zone(), &response)
            .unwrap_err()
            .contains("ID mismatch")
    );
}

#[test]
fn extract_soa_serial_rejects_error_rcode() {
    // RCODE 5 (REFUSED)
    let response = build_soa_response(42, 0x8405, "example.com", true, 2026);
    assert_eq!(
        extract_soa_serial(42, &zone(), &response).unwrap_err(),
        "RCODE 5"
    );
}

#[test]
fn extract_soa_serial_rejects_missing_qr_bit() {
    let response = build_soa_response(42, 0x0400, "example.com", true, 2026);
    assert!(
        extract_soa_serial(42, &zone(), &response)
            .unwrap_err()
            .contains("QR bit")
    );
}

#[test]
fn extract_soa_serial_rejects_truncated_response() {
    let response = build_soa_response(42, 0x8600, "example.com", true, 2026);
    assert_eq!(
        extract_soa_serial(42, &zone(), &response).unwrap_err(),
        "truncated response"
    );
}

#[test]
fn extract_soa_serial_rejects_answer_without_soa() {
    let response = build_soa_response(42, 0x8400, "example.com", false, 0);
    assert_eq!(
        extract_soa_serial(42, &zone(), &response).unwrap_err(),
        "no SOA record in answer"
    );
}

#[test]
fn extract_soa_serial_rejects_a_cache_or_another_question() {
    // 0x8000 = QR without AA: a cache answered, not the secondary.
    let cached = build_soa_response(42, 0x8000, "example.com", true, 2026);
    assert_eq!(
        extract_soa_serial(42, &zone(), &cached).unwrap_err(),
        "response is not authoritative"
    );
    let other = build_soa_response(42, 0x8400, "other.com", true, 2026);
    assert_eq!(
        extract_soa_serial(42, &zone(), &other).unwrap_err(),
        "response answers another question"
    );
}
