use super::{validate_expires_in_days, validate_token_name};
use crate::error::ErrorCode;

#[test]
fn validate_token_name_trims_and_accepts_plain_names() {
    assert_eq!(
        validate_token_name(" external-dns ").unwrap(),
        "external-dns"
    );
}

#[test]
fn validate_token_name_rejects_empty_and_whitespace_names() {
    for name in ["", "   ", "bad name", "bad\tname"] {
        let err = validate_token_name(name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}

#[test]
fn validate_expires_in_days_accepts_none_and_positive_values() {
    validate_expires_in_days(None).unwrap();
    validate_expires_in_days(Some(1)).unwrap();
}

#[test]
fn validate_expires_in_days_rejects_non_positive_values() {
    let zero = validate_expires_in_days(Some(0)).unwrap_err();
    let negative = validate_expires_in_days(Some(-1)).unwrap_err();

    assert_eq!(zero.code, ErrorCode::InvalidInput);
    assert_eq!(negative.code, ErrorCode::InvalidInput);
}
