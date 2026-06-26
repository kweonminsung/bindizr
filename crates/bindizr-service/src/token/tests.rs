use super::validate_expires_in_days;
use crate::error::ServiceError;

#[test]
fn validate_expires_in_days_accepts_none_and_positive_values() {
    validate_expires_in_days(None).unwrap();
    validate_expires_in_days(Some(1)).unwrap();
}

#[test]
fn validate_expires_in_days_rejects_non_positive_values() {
    let zero = validate_expires_in_days(Some(0)).unwrap_err();
    let negative = validate_expires_in_days(Some(-1)).unwrap_err();

    assert!(matches!(zero, ServiceError::BadRequest(_)));
    assert!(matches!(negative, ServiceError::BadRequest(_)));
}
