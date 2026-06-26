use super::*;

fn notify_response(query_id: u16, flags: u16) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query_id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

#[test]
fn validate_notify_response_accepts_matching_noerror_response() {
    let response = notify_response(1234, 0xa000);

    assert!(validate_notify_response(1234, &response).is_ok());
}

#[test]
fn validate_notify_response_rejects_id_mismatch() {
    let response = notify_response(1234, 0xa000);

    let err = validate_notify_response(5678, &response).unwrap_err();

    assert!(err.to_string().contains("ID mismatch"));
}

#[test]
fn validate_notify_response_rejects_error_rcode() {
    let response = notify_response(1234, 0xa005);

    let err = validate_notify_response(1234, &response).unwrap_err();

    assert!(err.to_string().contains("RCODE 5"));
}
