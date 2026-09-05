use super::{expires_at, normalize_token_name};
use crate::error::ErrorCode;

#[test]
fn normalize_token_name_trims_and_folds_case() {
    assert_eq!(
        normalize_token_name(" external-dns ").unwrap(),
        "external-dns"
    );
    assert_eq!(normalize_token_name("Deploy").unwrap(), "deploy");
    assert_eq!(
        normalize_token_name("DEPLOY").unwrap(),
        normalize_token_name("deploy").unwrap()
    );
}

#[test]
fn normalize_token_name_rejects_empty_and_whitespace_names() {
    for name in ["", "   ", "bad name", "bad\tname"] {
        let err = normalize_token_name(name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}

#[test]
fn expires_at_is_none_without_days_and_ahead_of_now_with_them() {
    assert!(expires_at(None).unwrap().is_none());
    assert!(expires_at(Some(1)).unwrap().unwrap() > chrono::Utc::now());
}

#[test]
fn expires_at_rejects_non_positive_values() {
    let zero = expires_at(Some(0)).unwrap_err();
    let negative = expires_at(Some(-1)).unwrap_err();

    assert_eq!(zero.code, ErrorCode::InvalidInput);
    assert_eq!(negative.code, ErrorCode::InvalidInput);
}

// `Duration::days` overflows before `i64::MAX`; the date addition, earlier still.
#[test]
fn expires_at_rejects_values_past_the_calendar() {
    let past_duration = expires_at(Some(i64::MAX)).unwrap_err();
    let past_date = expires_at(Some(400_000 * 366)).unwrap_err();

    assert_eq!(past_duration.code, ErrorCode::InvalidInput);
    assert_eq!(past_date.code, ErrorCode::InvalidInput);
}
