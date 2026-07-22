use base64::Engine;

use super::{generate_secret, normalize_key_name, parse_algorithm, validate_secret};
use crate::{error::ErrorCode, model::tsig_key::TsigAlgorithm};

#[test]
fn normalize_key_name_lowercases_and_strips_trailing_dot() {
    assert_eq!(
        normalize_key_name("Nsupdate-Key.Example.COM.").unwrap(),
        "nsupdate-key.example.com"
    );
    assert_eq!(normalize_key_name(" update-key ").unwrap(), "update-key");
}

#[test]
fn normalize_key_name_rejects_invalid_names() {
    for invalid in ["", ".", "bad name", "bad..label", &"a".repeat(300)] {
        let err = normalize_key_name(invalid).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput, "input: {:?}", invalid);
    }
}

#[test]
fn parse_algorithm_defaults_to_hmac_sha256() {
    assert_eq!(parse_algorithm(None).unwrap(), TsigAlgorithm::HmacSha256);
    assert_eq!(
        parse_algorithm(Some("HMAC-SHA512")).unwrap(),
        TsigAlgorithm::HmacSha512
    );
    assert_eq!(
        parse_algorithm(Some("hmac-sha384.")).unwrap(),
        TsigAlgorithm::HmacSha384
    );
}

#[test]
fn parse_algorithm_rejects_unsupported_names() {
    let err = parse_algorithm(Some("hmac-md5")).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

#[test]
fn validate_secret_accepts_base64_and_rejects_garbage() {
    // 32-byte imported secret, whitespace trimmed.
    assert_eq!(
        validate_secret(" bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU= ").unwrap(),
        "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=".to_string()
    );

    let invalid = validate_secret("not base64!!").unwrap_err();
    assert_eq!(invalid.code, ErrorCode::InvalidInput);

    let empty = validate_secret("").unwrap_err();
    assert_eq!(empty.code, ErrorCode::InvalidInput);
}

#[test]
fn validate_secret_enforces_length_bounds() {
    // 6 decoded bytes: far below the 128-bit minimum.
    let short = validate_secret("c2VjcmV0").unwrap_err();
    assert_eq!(short.code, ErrorCode::InvalidInput);
    assert!(short.message.contains("at least 16 bytes"));

    // Exactly 16 decoded bytes passes.
    let sixteen = base64::engine::general_purpose::STANDARD.encode([0x42u8; 16]);
    validate_secret(&sixteen).unwrap();

    // The base64 form must fit the VARCHAR(255) column.
    let oversized = base64::engine::general_purpose::STANDARD.encode([0x42u8; 200]);
    assert!(oversized.len() > 255);
    let too_long = validate_secret(&oversized).unwrap_err();
    assert_eq!(too_long.code, ErrorCode::InvalidInput);
    assert!(too_long.message.contains("at most 255"));
}

#[test]
fn generate_secret_produces_32_random_base64_bytes() {
    let first = generate_secret();
    let second = generate_secret();

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&first)
        .unwrap();
    assert_eq!(decoded.len(), 32);
    assert_ne!(first, second);
}
