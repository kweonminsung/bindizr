use super::validate_expires_in_days;
use crate::error::{ErrorCode, ServiceError};

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
