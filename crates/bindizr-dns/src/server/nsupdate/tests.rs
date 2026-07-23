use super::{parser::tests::minimal_update_with_ztype, *};
use crate::protocol::TYPE_TSIG;

#[test]
fn build_response_appends_tsig_error_rr() {
    let response = build_response(
        &minimal_update_with_ztype(6),
        NsupdateResponse {
            rcode: RCODE_NOTAUTH,
            tsig: Some(ResponseTsig::Unsigned(TsigErrorResponse {
                name_canonical: vec![3, b'k', b'e', b'y', 0],
                algorithm_canonical: vec![
                    11, b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'5', b'6', 0,
                ],
                original_id: 0x1234,
                time_signed: 1,
                fudge: 300,
                error: 16,
                other_data: Vec::new(),
            })),
        },
    )
    .unwrap();

    assert_eq!(response[3] & 0x0f, RCODE_NOTAUTH);
    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);
    assert!(response.windows(2).any(|w| w == TYPE_TSIG.to_be_bytes()));
    assert!(response.windows(2).any(|w| w == 16u16.to_be_bytes()));
}
