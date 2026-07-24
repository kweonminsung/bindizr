use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use super::*;
use crate::model::tsig_key::{TsigAlgorithm, TsigKey};

const SECRET: &[u8] = b"a-very-secret-test-key-material!";

fn encode_name(name: &str) -> Vec<u8> {
    use std::str::FromStr;
    domain::base::Name::<Vec<u8>>::from_str(&name.to_ascii_lowercase())
        .unwrap()
        .as_slice()
        .to_vec()
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
        } => match *tsig {
            ResponseTsig::Unsigned(tsig) => tsig.error,
            ResponseTsig::Signed(signer) => signer.error,
        },
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
fn validate_tsig_rejects_stale_time_with_signed_badtime() {
    let stale = now_secs() - 3600;
    let (query, tsig) = signed_request(TsigAlgorithm::HmacSha256, stale);

    let err = validate_tsig(&tsig, &query, &test_key(TsigAlgorithm::HmacSha256)).unwrap_err();
    // RFC 8945 §5.2.3: BADTIME responses are signed, echo the client's time,
    // and carry the server's time in other data.
    match err {
        UpdateError::NotAuth {
            tsig: Some(tsig), ..
        } => match *tsig {
            ResponseTsig::Signed(signer) => {
                assert_eq!(signer.error, TSIG_ERROR_BADTIME);
                assert_eq!(signer.time_signed, Some(stale));
                assert_eq!(signer.other_data.len(), 6);
            }
            other => panic!("expected signed BADTIME response, got {:?}", other),
        },
        other => panic!("expected signed BADTIME response, got {:?}", other),
    }
}

#[test]
fn sign_response_appends_verifiable_tsig() {
    let (query, tsig) = signed_request(TsigAlgorithm::HmacSha256, now_secs());
    let key = test_key(TsigAlgorithm::HmacSha256);
    let signer = validate_tsig(&tsig, &query, &key).unwrap();

    // Minimal NOERROR response header echoing the request ID.
    let mut response = vec![0u8; 12];
    response[0] = 0x12;
    response[1] = 0x34;
    response[2] = 0x80 | 0x28;
    let unsigned = response.clone();

    signer.sign_response(&mut response).unwrap();

    assert_eq!(u16::from_be_bytes([response[10], response[11]]), 1);

    // Parse the appended TSIG RR.
    let mut off = unsigned.len();
    assert_eq!(
        &response[off..off + tsig.name_canonical.len()],
        &tsig.name_canonical[..]
    );
    off += tsig.name_canonical.len();
    assert_eq!(
        u16::from_be_bytes([response[off], response[off + 1]]),
        crate::protocol::TYPE_TSIG
    );
    off += 2 + 2 + 4 + 2; // type, class, ttl, rdlen
    assert_eq!(
        &response[off..off + tsig.algorithm_canonical.len()],
        &tsig.algorithm_canonical[..]
    );
    off += tsig.algorithm_canonical.len();
    let time_signed = response[off..off + 6]
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    off += 6;
    let fudge = u16::from_be_bytes([response[off], response[off + 1]]);
    off += 2;
    assert_eq!(fudge, tsig.fudge);
    let mac_len = u16::from_be_bytes([response[off], response[off + 1]]) as usize;
    off += 2;
    let mac = response[off..off + mac_len].to_vec();
    off += mac_len;
    assert_eq!(
        u16::from_be_bytes([response[off], response[off + 1]]),
        0x1234
    );
    off += 2;
    assert_eq!(u16::from_be_bytes([response[off], response[off + 1]]), 0); // error
    off += 2;
    assert_eq!(u16::from_be_bytes([response[off], response[off + 1]]), 0); // other len
    off += 2;
    assert_eq!(off, response.len());

    // Recompute the MAC per RFC 8945 §4.3.3: request MAC (length-prefixed),
    // the unsigned response, then the TSIG variables.
    let mut data = Vec::new();
    data.extend_from_slice(&(tsig.mac.len() as u16).to_be_bytes());
    data.extend_from_slice(&tsig.mac);
    data.extend_from_slice(&unsigned);
    data.extend_from_slice(&tsig.name_canonical);
    data.extend_from_slice(&crate::protocol::CLASS_ANY.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&tsig.algorithm_canonical);
    data.extend_from_slice(&encode_u48(time_signed));
    data.extend_from_slice(&tsig.fudge.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes());

    let mut expected = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    expected.update(&data);
    assert_eq!(mac, expected.finalize().into_bytes().to_vec());
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
