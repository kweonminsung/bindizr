use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use super::*;
use crate::model::tsig_key::{TsigAlgorithm, TsigKey};

const SECRET: &[u8] = b"a-very-secret-test-key-material!";

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    crate::wire::encode_domain_name(&name.to_ascii_lowercase(), &mut out).unwrap();
    out
}

fn test_key(algorithm: TsigAlgorithm) -> TsigKey {
    TsigKey {
        id: 1,
        name: "update-key".to_string(),
        algorithm,
        secret: base64::engine::general_purpose::STANDARD.encode(SECRET),
        is_global: false,
        created_at: Utc::now(),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A minimal UPDATE message: header with ARCOUNT=1 plus opaque filler standing
/// in for the TSIG RR (its bytes are stripped before signing anyway).
fn signed_request(algorithm: TsigAlgorithm, time_signed: u64) -> (Vec<u8>, TsigRecord) {
    let mut query = vec![
        0x12, 0x34, // ID
        0x28, 0x00, // opcode UPDATE
        0x00, 0x00, // ZOCOUNT
        0x00, 0x00, // PRCOUNT
        0x00, 0x00, // UPCOUNT
        0x00, 0x01, // ARCOUNT (the TSIG RR)
    ];
    let rr_start = query.len();
    query.extend_from_slice(&[0xAA; 16]);
    let rr_end = query.len();

    let mut tsig = TsigRecord {
        name: "update-key".to_string(),
        name_canonical: encode_name("update-key"),
        algorithm: algorithm.as_str().to_string(),
        algorithm_canonical: encode_name(algorithm.as_str()),
        time_signed,
        fudge: 300,
        mac: Vec::new(),
        original_id: 0x1234,
        error: 0,
        other_data: Vec::new(),
        rr_start,
        rr_end,
    };

    let signed_data = build_tsig_signed_data(&query, &tsig).unwrap();
    tsig.mac = match algorithm {
        TsigAlgorithm::HmacSha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
            mac.update(&signed_data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlgorithm::HmacSha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(SECRET).unwrap();
            mac.update(&signed_data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlgorithm::HmacSha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(SECRET).unwrap();
            mac.update(&signed_data);
            mac.finalize().into_bytes().to_vec()
        }
    };

    (query, tsig)
}

fn tsig_error_code(err: UpdateError) -> u16 {
    match err {
        UpdateError::NotAuth {
            tsig: Some(tsig), ..
        } => tsig.error,
        other => panic!("expected NotAuth with TSIG error, got {:?}", other),
    }
}

#[test]
fn validate_tsig_accepts_valid_signatures_for_all_algorithms() {
    for algorithm in [
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let (query, tsig) = signed_request(algorithm, now_secs());
        validate_tsig(&tsig, &query, &test_key(algorithm)).unwrap();
    }
}

#[test]
fn validate_tsig_rejects_tampered_mac_with_badsig() {
    let (query, mut tsig) = signed_request(TsigAlgorithm::HmacSha256, now_secs());
    tsig.mac[0] ^= 0xFF;

    let err = validate_tsig(&tsig, &query, &test_key(TsigAlgorithm::HmacSha256)).unwrap_err();
    assert_eq!(tsig_error_code(err), TSIG_ERROR_BADSIG);
}

#[test]
fn validate_tsig_rejects_algorithm_mismatch_with_badkey() {
    let (query, tsig) = signed_request(TsigAlgorithm::HmacSha256, now_secs());

    let err = validate_tsig(&tsig, &query, &test_key(TsigAlgorithm::HmacSha512)).unwrap_err();
    assert_eq!(tsig_error_code(err), TSIG_ERROR_BADKEY);
}

#[test]
fn validate_tsig_rejects_unsupported_wire_algorithm_with_badkey() {
    let (query, mut tsig) = signed_request(TsigAlgorithm::HmacSha256, now_secs());
    tsig.algorithm = "hmac-md5.sig-alg.reg.int".to_string();

    let err = validate_tsig(&tsig, &query, &test_key(TsigAlgorithm::HmacSha256)).unwrap_err();
    assert_eq!(tsig_error_code(err), TSIG_ERROR_BADKEY);
}

#[test]
fn validate_tsig_rejects_stale_time_with_badtime() {
    let stale = now_secs() - 3600;
    let (query, tsig) = signed_request(TsigAlgorithm::HmacSha256, stale);

    let err = validate_tsig(&tsig, &query, &test_key(TsigAlgorithm::HmacSha256)).unwrap_err();
    assert_eq!(tsig_error_code(err), TSIG_ERROR_BADTIME);
}

#[test]
fn validate_tsig_rejects_original_id_mismatch_with_badsig() {
    let (query, mut tsig) = signed_request(TsigAlgorithm::HmacSha256, now_secs());
    tsig.original_id = 0x9999;

    let err = validate_tsig(&tsig, &query, &test_key(TsigAlgorithm::HmacSha256)).unwrap_err();
    assert_eq!(tsig_error_code(err), TSIG_ERROR_BADSIG);
}

#[test]
fn unknown_key_error_reports_badkey() {
    let (_, tsig) = signed_request(TsigAlgorithm::HmacSha256, now_secs());
    assert_eq!(tsig_error_code(unknown_key_error(&tsig)), TSIG_ERROR_BADKEY);
}
