use super::{MAX_EXPIRES_IN_DAYS, normalize_expires_at, normalize_token_name};
use crate::error::ErrorCode;

/// Verify that `normalize_token_name` trims and folds case.
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

/// Verify that `normalize_token_name` rejects empty and whitespace names.
#[test]
fn normalize_token_name_rejects_empty_and_whitespace_names() {
    for name in ["", "   ", "bad name", "bad\tname"] {
        let err = normalize_token_name(name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}

/// Verify rejection of token names that cannot remain one URL path segment.
///
/// `/` splits segments, `?` and `#` terminate them, and URL normalization removes dot segments.
#[test]
fn normalize_token_name_rejects_names_that_are_not_one_path_segment() {
    for name in [".", "..", "self", "a/b", "a?b", "a#b", "a%2fb", "토큰"] {
        let err = normalize_token_name(name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{name}");
    }
    assert_eq!(
        normalize_token_name("ci.prod_v2-x").unwrap(),
        "ci.prod_v2-x"
    );
}

/// Verify that `normalize_expires_at` is none without days and ahead of now with them.
#[test]
fn to_expires_at_is_none_without_days_and_ahead_of_now_with_them() {
    assert!(normalize_expires_at(None).unwrap().is_none());
    assert!(normalize_expires_at(Some(1)).unwrap().unwrap() > chrono::Utc::now());
    assert!(normalize_expires_at(Some(MAX_EXPIRES_IN_DAYS)).is_ok());
}

/// Verify that `normalize_expires_at` rejects non positive values.
#[test]
fn to_expires_at_rejects_non_positive_values() {
    let zero = normalize_expires_at(Some(0)).unwrap_err();
    let negative = normalize_expires_at(Some(-1)).unwrap_err();

    assert_eq!(zero.code, ErrorCode::InvalidInput);
    assert_eq!(negative.code, ErrorCode::InvalidInput);
}

/// Verify that `normalize_expires_at` rejects values beyond the cap.
#[test]
fn to_expires_at_rejects_values_beyond_the_cap() {
    let just_over = normalize_expires_at(Some(MAX_EXPIRES_IN_DAYS + 1)).unwrap_err();
    let overflow = normalize_expires_at(Some(i64::MAX)).unwrap_err();

    assert_eq!(just_over.code, ErrorCode::InvalidInput);
    assert_eq!(overflow.code, ErrorCode::InvalidInput);
}
