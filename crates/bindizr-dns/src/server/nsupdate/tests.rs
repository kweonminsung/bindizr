use super::*;

fn minimal_update_query() -> Vec<u8> {
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
    message.extend_from_slice(&6u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message
}

#[test]
fn build_response_appends_tsig_error_rr() {
    let response = build_response(
        &minimal_update_query(),
        NsupdateResponse {
            rcode: RCODE_NOTAUTH,
            tsig: Some(TsigErrorResponse {
                name_canonical: vec![3, b'k', b'e', b'y', 0],
                algorithm_canonical: vec![
                    11, b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'5', b'6', 0,
                ],
                original_id: 0x1234,
                time_signed: 1,
                fudge: 300,
                error: 16,
                other_data: Vec::new(),
            }),
        },
    )
    .unwrap();

    assert_eq!(response[3] & 0x0f, RCODE_NOTAUTH);
    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
    assert!(response.windows(2).any(|w| w == TYPE_TSIG.to_be_bytes()));
    assert!(response.windows(2).any(|w| w == 16u16.to_be_bytes()));
}
