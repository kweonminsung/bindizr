use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::Utc;
use domain::base::iana::{Class, Rtype};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use super::*;
use crate::dns::nsupdate::parser::tests::minimal_update_with_ztype;

pub(crate) const SECRET: &[u8] = b"a-very-secret-test-key-material!";

pub(crate) fn test_key(algorithm: TsigAlgorithm) -> TsigKey {
    TsigKey {
        id: 1,
        name: "update-key".to_string(),
        algorithm,
        secret: base64::engine::general_purpose::STANDARD.encode(SECRET),
        is_global: false,
        created_at: Utc::now(),
    }
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(crate) fn encode_name(name: &str) -> Vec<u8> {
    domain::base::Name::<Vec<u8>>::from_str(name)
        .unwrap()
        .as_slice()
        .to_vec()
}

pub(crate) fn encode_u48(value: u64) -> [u8; 6] {
    let bytes = value.to_be_bytes();
    [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
}

pub(crate) fn hmac_sign(algorithm: TsigAlgorithm, data: &[u8]) -> Vec<u8> {
    macro_rules! sign_with {
        ($digest:ty) => {{
            let mut mac = Hmac::<$digest>::new_from_slice(SECRET).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }

    match algorithm {
        TsigAlgorithm::HmacSha256 => sign_with!(Sha256),
        TsigAlgorithm::HmacSha384 => sign_with!(Sha384),
        TsigAlgorithm::HmacSha512 => sign_with!(Sha512),
    }
}

/// A minimal UPDATE request signed with `update-key`: the MAC covers the
/// message without the TSIG RR plus the TSIG variables (RFC 8945, Sections 4.3.2 and 4.3.3).
pub(crate) fn signed_update(algorithm: TsigAlgorithm, time_signed: u64) -> Vec<u8> {
    let base = minimal_update_with_ztype(6);
    let key_name = encode_name("update-key");
    let algorithm_name = encode_name(algorithm.as_str());

    let mut digest = base.clone();
    digest.extend_from_slice(&key_name);
    digest.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    digest.extend_from_slice(&0u32.to_be_bytes());
    digest.extend_from_slice(&algorithm_name);
    digest.extend_from_slice(&encode_u48(time_signed));
    digest.extend_from_slice(&300u16.to_be_bytes());
    digest.extend_from_slice(&0u16.to_be_bytes()); // error
    digest.extend_from_slice(&0u16.to_be_bytes()); // other len
    let mac = hmac_sign(algorithm, &digest);

    let mut message = base;
    message[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    message.extend_from_slice(&key_name);
    message.extend_from_slice(&Rtype::TSIG.to_int().to_be_bytes());
    message.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes()); // TTL
    let rdlen = algorithm_name.len() + 6 + 2 + 2 + mac.len() + 2 + 2 + 2;
    message.extend_from_slice(&(rdlen as u16).to_be_bytes());
    message.extend_from_slice(&algorithm_name);
    message.extend_from_slice(&encode_u48(time_signed));
    message.extend_from_slice(&300u16.to_be_bytes());
    message.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    message.extend_from_slice(&mac);
    message.extend_from_slice(&[0x12, 0x34]); // original ID (= header ID)
    message.extend_from_slice(&0u16.to_be_bytes()); // error
    message.extend_from_slice(&0u16.to_be_bytes()); // other len
    message
}

/// Parse the response's rcode plus TSIG error, time-signed, MAC, and other
/// data.
fn response_tsig(response: &[u8]) -> (Rcode, TsigRcode, u64, Vec<u8>, Vec<u8>) {
    let msg = Message::from_octets(response).unwrap();
    let record = msg
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let data = record.data();

    (
        msg.header().rcode(),
        data.error(),
        u64::from(data.time_signed()),
        data.mac().to_vec(),
        data.other().to_vec(),
    )
}

fn failed_response(err: TsigError) -> Vec<u8> {
    match err {
        TsigError::Failed { response, .. } => response,
        other => panic!("expected TsigFailed, got {:?}", other),
    }
}

#[test]
fn validate_tsig_accepts_valid_signatures_for_all_algorithms() {
    for algorithm in [
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let query = signed_update(algorithm, now_secs());
        let key = to_domain_key(&test_key(algorithm)).unwrap();
        validate_tsig(&query, Some(key)).unwrap();
    }
}

#[test]
fn validate_tsig_rejects_tampered_mac_with_badsig() {
    let mut query = signed_update(TsigAlgorithm::HmacSha256, now_secs());
    // The last 6 rdata bytes are original ID, error, and other-len; the byte
    // before them is the MAC's last byte.
    let mac_end = query.len() - 7;
    query[mac_end] ^= 0xFF;

    let key = to_domain_key(&test_key(TsigAlgorithm::HmacSha256)).unwrap();
    let err = validate_tsig(&query, Some(key)).unwrap_err();

    // RFC 8945, Section 5.3.2: a MAC failure answers NOTAUTH/BADSIG with an unsigned
    // TSIG error record.
    let (rcode, error, _, mac, _) = response_tsig(&failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADSIG);
    assert!(mac.is_empty());
}

#[test]
fn validate_tsig_rejects_original_id_mismatch_with_badsig() {
    let mut query = signed_update(TsigAlgorithm::HmacSha256, now_secs());
    // Flip the original ID (first two of the trailing six rdata bytes): the
    // MAC is computed over the original ID, so verification must fail.
    let original_id = query.len() - 6;
    query[original_id] ^= 0xFF;

    let key = to_domain_key(&test_key(TsigAlgorithm::HmacSha256)).unwrap();
    let err = validate_tsig(&query, Some(key)).unwrap_err();

    let (rcode, error, _, _, _) = response_tsig(&failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADSIG);
}

#[test]
fn validate_tsig_rejects_algorithm_mismatch_with_badkey() {
    let query = signed_update(TsigAlgorithm::HmacSha256, now_secs());

    let key = to_domain_key(&test_key(TsigAlgorithm::HmacSha512)).unwrap();
    let err = validate_tsig(&query, Some(key)).unwrap_err();

    let (rcode, error, _, mac, _) = response_tsig(&failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADKEY);
    assert!(mac.is_empty());
}

#[test]
fn validate_tsig_rejects_unknown_key_with_badkey() {
    let query = signed_update(TsigAlgorithm::HmacSha256, now_secs());

    let err = validate_tsig(&query, None).unwrap_err();

    let (rcode, error, _, mac, _) = response_tsig(&failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADKEY);
    assert!(mac.is_empty());
}

#[test]
fn validate_tsig_rejects_stale_time_with_signed_badtime() {
    let stale = now_secs() - 3600;
    let query = signed_update(TsigAlgorithm::HmacSha256, stale);

    let key = to_domain_key(&test_key(TsigAlgorithm::HmacSha256)).unwrap();
    let err = validate_tsig(&query, Some(key)).unwrap_err();

    // RFC 8945, Section 5.2.3: BADTIME responses are signed, echo the client's time,
    // and carry the server's time in other data.
    let (rcode, error, time_signed, mac, other) = response_tsig(&failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADTIME);
    assert_eq!(time_signed, stale);
    assert_eq!(other.len(), 6);
    assert!(!mac.is_empty());
}
