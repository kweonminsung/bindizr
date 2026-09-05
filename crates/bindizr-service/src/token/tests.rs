use super::{MAX_EXPIRES_IN_DAYS, expires_at, normalize_token_name, validate_token_description};
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

// `/` splits a path segment, `?` and `#` end it, and dot segments get normalized away.
#[test]
fn normalize_token_name_rejects_names_that_are_not_one_path_segment() {
    for name in [".", "..", "a/b", "a?b", "a#b", "a%2fb", "토큰"] {
        let err = normalize_token_name(name).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "{name}");
    }
    assert_eq!(
        normalize_token_name("ci.prod_v2-x").unwrap(),
        "ci.prod_v2-x"
    );
}

#[test]
fn expires_at_is_none_without_days_and_ahead_of_now_with_them() {
    assert!(expires_at(None).unwrap().is_none());
    assert!(expires_at(Some(1)).unwrap().unwrap() > chrono::Utc::now());
    assert!(expires_at(Some(MAX_EXPIRES_IN_DAYS)).is_ok());
}

#[test]
fn expires_at_rejects_non_positive_values() {
    let zero = expires_at(Some(0)).unwrap_err();
    let negative = expires_at(Some(-1)).unwrap_err();

    assert_eq!(zero.code, ErrorCode::InvalidInput);
    assert_eq!(negative.code, ErrorCode::InvalidInput);
}

#[test]
fn expires_at_rejects_values_beyond_the_cap() {
    let just_over = expires_at(Some(MAX_EXPIRES_IN_DAYS + 1)).unwrap_err();
    let overflow = expires_at(Some(i64::MAX)).unwrap_err();

    assert_eq!(just_over.code, ErrorCode::InvalidInput);
    assert_eq!(overflow.code, ErrorCode::InvalidInput);
}

#[test]
fn validate_token_description_counts_characters_and_rejects_nul() {
    validate_token_description(None).unwrap();
    validate_token_description(Some(&"é".repeat(255))).unwrap();

    let too_long = validate_token_description(Some(&"é".repeat(256))).unwrap_err();
    let nul = validate_token_description(Some("a\0b")).unwrap_err();

    assert_eq!(too_long.code, ErrorCode::InvalidInput);
    assert_eq!(nul.code, ErrorCode::InvalidInput);
}
