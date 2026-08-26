use super::extract_soa_serial;

fn encode_name(name: &str, buf: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn build_soa_response(query_id: u16, flags: u16, with_answer: bool, serial: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&query_id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&(u16::from(with_answer)).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    encode_name("example.com", &mut buf);
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    if with_answer {
        encode_name("example.com", &mut buf);
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
fn extracts_serial_from_soa_answer() {
    // 0x8400 = QR + AA, NOERROR.
    let response = build_soa_response(42, 0x8400, true, 2026);
    assert_eq!(extract_soa_serial(42, &response).unwrap(), 2026);
}

#[test]
fn rejects_id_mismatch() {
    let response = build_soa_response(42, 0x8400, true, 2026);
    assert!(
        extract_soa_serial(7, &response)
            .unwrap_err()
            .contains("ID mismatch")
    );
}

#[test]
fn rejects_error_rcode() {
    // RCODE 5 (REFUSED)
    let response = build_soa_response(42, 0x8405, true, 2026);
    assert_eq!(extract_soa_serial(42, &response).unwrap_err(), "RCODE 5");
}

#[test]
fn rejects_missing_qr_bit() {
    let response = build_soa_response(42, 0x0400, true, 2026);
    assert!(
        extract_soa_serial(42, &response)
            .unwrap_err()
            .contains("QR bit")
    );
}

#[test]
fn rejects_truncated_response() {
    let response = build_soa_response(42, 0x8600, true, 2026);
    assert_eq!(
        extract_soa_serial(42, &response).unwrap_err(),
        "truncated response"
    );
}

#[test]
fn rejects_answer_without_soa() {
    let response = build_soa_response(42, 0x8400, false, 0);
    assert_eq!(
        extract_soa_serial(42, &response).unwrap_err(),
        "no SOA record in answer"
    );
}
