use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::Utc;
use domain::{
    base::{
        MessageBuilder, Name,
        iana::{Class, Opcode, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    tsig::ServerTransaction,
};
use ring::hmac;

use super::*;
use crate::{
    dns::nsupdate::parser::tests::minimal_update_with_ztype,
    model::{role::RoleId, tsig_key::TsigKeyId},
};

const SECRET: &[u8] = b"a-very-secret-test-key-material!";

/// Fixed TSIG fields are checked even when altering them leaves the MAC unchanged.
#[test]
fn verify_response_rejects_invalid_class_and_ttl() {
    let key = test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let mut question = MessageBuilder::new_vec().question();
    question
        .push((
            Name::<Vec<u8>>::from_str("example.com.").unwrap(),
            Rtype::SOA,
        ))
        .unwrap();
    let mut query = question.additional();
    let verifier = sign_request(&mut query, key.clone()).unwrap();
    let query = query.finish();
    let server = verify_tsig(
        &query,
        Some(key),
        crate::dns::message::ResponseLimit::STREAM,
    )
    .unwrap();
    let query = Message::from_octets(query).unwrap();
    let mut response = MessageBuilder::new_vec()
        .start_answer(&query, Rcode::NOERROR)
        .unwrap()
        .additional();
    server.sign_response(&mut response, Time48::now()).unwrap();
    let response = response.finish();
    verify_response(&verifier, &response).unwrap();
    let start = Message::from_octets(response.as_slice())
        .unwrap()
        .additional()
        .unwrap()
        .pos();
    let mut parser = Parser::from_ref(response.as_slice());
    parser.seek(start).unwrap();
    ParsedName::skip(&mut parser).unwrap();
    let fields = parser.pos();
    for (offset, bytes) in [(fields + 2, vec![0, 1]), (fields + 4, vec![0, 0, 0, 1])] {
        let mut modified = response.clone();
        modified[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let error = verify_response(&verifier, &modified).unwrap_err();
        assert!(!error.is_authenticated());
    }
    let mut other = response;
    let end = other.len();
    let rdlen_offset = fields + 8;
    let rdlen = u16::from_be_bytes([other[rdlen_offset], other[rdlen_offset + 1]]);
    other[rdlen_offset..rdlen_offset + 2].copy_from_slice(&(rdlen + 1).to_be_bytes());
    other[end - 2..].copy_from_slice(&1u16.to_be_bytes());
    other.push(0x7f);
    assert!(
        !verify_response(&verifier, &other)
            .unwrap_err()
            .is_authenticated()
    );
}

/// A request cannot carry a TSIG response error, even under a valid MAC.
#[test]
fn request_tsig_rejects_nonzero_error() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let key = test_key(algorithm).to_signing_key().unwrap();
        for error in [
            TsigRcode::BADSIG,
            TsigRcode::BADKEY,
            TsigRcode::BADTIME,
            TsigRcode::BADTRUNC,
        ] {
            let message = build_signed_update_with_tsig_fields(algorithm, now_secs(), error, &[]);
            assert_eq!(request_signature(&message), RequestSignature::Malformed);
            assert!(matches!(
                crate::dns::nsupdate::parser::UpdateRequest::parse(&message),
                Err(crate::dns::nsupdate::parser::ParseUpdateError::InvalidTsig)
            ));
            assert!(matches!(
                verify_tsig(
                    &message,
                    Some(key.clone()),
                    crate::dns::message::ResponseLimit::STREAM
                ),
                Err(TsigError::Malformed(_))
            ));
        }
    }
}

/// Other Data is opaque in requests and every octet participates in the MAC.
#[test]
fn verify_tsig_authenticates_original_other_data() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let key = test_key(algorithm).to_signing_key().unwrap();
        for other in [&[0x7f][..], &[0; 6], &[0xff; 8], &[0x42; 32]] {
            let query = build_signed_update_with_tsig_fields(
                algorithm,
                now_secs(),
                TsigRcode::NOERROR,
                other,
            );
            let signer = verify_tsig(
                &query,
                Some(key.clone()),
                crate::dns::message::ResponseLimit::STREAM,
            )
            .unwrap();
            let message = Message::from_octets(query.as_slice()).unwrap();
            let mut response = MessageBuilder::new_vec()
                .start_answer(&message, Rcode::NOERROR)
                .unwrap()
                .additional();
            signer.sign_response(&mut response, Time48::now()).unwrap();
            assert_response_mac(&query, &response.finish(), algorithm);
            let mut tampered = query;
            *tampered.last_mut().unwrap() ^= 1;
            let error = verify_tsig(
                &tampered,
                Some(key.clone()),
                crate::dns::message::ResponseLimit::STREAM,
            )
            .unwrap_err();
            assert_eq!(
                extract_response_tsig(&extract_failed_response(error)).1,
                TsigRcode::BADSIG
            );
        }
        let mut appended = build_signed_update(algorithm, now_secs());
        let message = Message::from_octets(appended.as_slice()).unwrap();
        let mut parser = Parser::from_ref(appended.as_slice());
        parser.seek(message.additional().unwrap().pos()).unwrap();
        ParsedName::skip(&mut parser).unwrap();
        let rdlen_offset = parser.pos() + 8;
        let rdlen = u16::from_be_bytes([appended[rdlen_offset], appended[rdlen_offset + 1]]);
        appended[rdlen_offset..rdlen_offset + 2].copy_from_slice(&(rdlen + 1).to_be_bytes());
        let end = appended.len();
        appended[end - 2..].copy_from_slice(&1u16.to_be_bytes());
        appended.push(0x7f);
        let error = verify_tsig(
            &appended,
            Some(key),
            crate::dns::message::ResponseLimit::STREAM,
        )
        .unwrap_err();
        assert_eq!(
            extract_response_tsig(&extract_failed_response(error)).1,
            TsigRcode::BADSIG
        );
    }
}

/// TSIG errors fit long queries and distinguish authenticated responses.
#[test]
fn tsig_errors_fit_long_compressed_queries_and_retain_authentication_status() {
    let name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let key = TsigKey {
        name: name.clone(),
        ..test_key(TsigAlgorithm::HmacSha512)
    }
    .to_signing_key()
    .unwrap();
    let truncated_key = Arc::new(
        Key::new(
            Algorithm::Sha512,
            SECRET,
            key.as_ref().name().clone(),
            None,
            Some(32),
        )
        .unwrap(),
    );
    let mut question = crate::dns::message::build_response().question();
    question
        .push((Name::<Vec<u8>>::from_str(&name).unwrap(), Rtype::SOA))
        .unwrap();
    let mut additional = question.additional();
    ClientTransaction::request(truncated_key, &mut additional, Time48::now()).unwrap();
    let query = additional.finish().into_target();
    let response = extract_failed_response(
        verify_tsig(
            &query,
            Some(key.clone()),
            crate::dns::message::ResponseLimit::STREAM,
        )
        .unwrap_err(),
    );
    assert!(response.len() <= 512);
    assert_eq!(extract_response_tsig(&response).1, TsigRcode::BADTRUNC);
    assert_response_mac(&query, &response, TsigAlgorithm::HmacSha512);
    for stale in [false, true] {
        let mut question = crate::dns::message::build_response().question();
        question
            .push((Name::<Vec<u8>>::from_str(&name).unwrap(), Rtype::SOA))
            .unwrap();
        let mut additional = question.additional();
        let time = Time48::from_u64(now_secs() - if stale { 3600 } else { 0 });
        let _client =
            ClientTransaction::request_with_fudge(key.clone(), &mut additional, time, 300).unwrap();
        let query = additional.finish().into_target();
        let request_message = Message::from_octets(query.as_slice()).unwrap();
        let request_tsig = request_message
            .additional()
            .unwrap()
            .limit_to::<Tsig<_, _>>()
            .last()
            .unwrap()
            .unwrap();
        let verifier = ResponseVerifier {
            key: key.clone(),
            request_mac: request_tsig.data().mac().to_vec(),
        };
        let unknown = extract_failed_response(
            verify_tsig(&query, None, crate::dns::message::ResponseLimit::STREAM).unwrap_err(),
        );
        assert!(unknown.len() <= 512);
        assert!(
            !verify_response(&verifier, &unknown)
                .unwrap_err()
                .is_authenticated()
        );
        if stale {
            let response = extract_failed_response(
                verify_tsig(
                    &query,
                    Some(key.clone()),
                    crate::dns::message::ResponseLimit::STREAM,
                )
                .unwrap_err(),
            );
            assert!(response.len() <= 512);
            assert_response_mac(&query, &response, TsigAlgorithm::HmacSha512);
            assert!(matches!(
                verify_response(&verifier, &response),
                Err(VerifyResponseError::ServerBadTime(_))
            ));
            let mut forged = response;
            let index = forged.len() - 13;
            forged[index] ^= 1;
            assert!(
                !verify_response(&verifier, &forged)
                    .unwrap_err()
                    .is_authenticated()
            );
        } else {
            let mut forged = query;
            forged[2] ^= 1;
            let response = extract_failed_response(
                verify_tsig(
                    &forged,
                    Some(key.clone()),
                    crate::dns::message::ResponseLimit::STREAM,
                )
                .unwrap_err(),
            );
            assert!(response.len() <= 512);
            assert_eq!(extract_response_tsig(&response).1, TsigRcode::BADSIG);
            assert!(
                !verify_response(&verifier, &response)
                    .unwrap_err()
                    .is_authenticated()
            );
        }
    }
}

/// Size bounds never erase the TSIG error, its time fields, or its full MAC.
#[test]
fn tsig_errors_with_distinct_long_names_fit_udp() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let native = test_key(algorithm)
            .to_signing_key()
            .unwrap()
            .as_ref()
            .native_len();
        for truncated in [false, true] {
            let mac_len = if truncated { native / 2 } else { native };
            let key = TsigKey {
                name: format!(
                    "{}.{}.{}.{}",
                    "k".repeat(63),
                    "l".repeat(63),
                    "m".repeat(63),
                    "n".repeat(
                        1 + 64 - mac_len + usize::from(algorithm == TsigAlgorithm::HmacSha1) * 2
                    )
                ),
                ..test_key(algorithm)
            }
            .to_signing_key()
            .unwrap();
            let client = Arc::new(
                Key::new(
                    key.as_ref().algorithm(),
                    SECRET,
                    key.as_ref().name().clone(),
                    None,
                    Some(mac_len),
                )
                .unwrap(),
            );
            for stale in [false, true] {
                if !stale && !truncated {
                    continue;
                }
                for edns in [None, Some(512), Some(1232)] {
                    for (opcode, qtype) in [
                        (Opcode::QUERY, Rtype::SOA),
                        (Opcode::QUERY, Rtype::AXFR),
                        (Opcode::UPDATE, Rtype::SOA),
                    ] {
                        for request_len in [506, 507, 509] {
                            let qname = format!(
                                "{}.{}.{}.d",
                                "a".repeat(63 - (509 - request_len)),
                                "b".repeat(63),
                                "c".repeat(if edns.is_some() { 52 } else { 63 })
                            );
                            let mut builder = MessageBuilder::new_vec();
                            builder.header_mut().set_id(8945);
                            builder.header_mut().set_opcode(opcode);
                            builder.header_mut().set_rd(true);
                            let mut question = builder.question();
                            question
                                .push((Name::<Vec<u8>>::from_str(&qname).unwrap(), qtype))
                                .unwrap();
                            let mut query = question.additional();
                            if let Some(size) = edns {
                                query
                                    .opt(|opt| {
                                        opt.set_udp_payload_size(size);
                                        opt.set_dnssec_ok(true);
                                        Ok(())
                                    })
                                    .unwrap();
                            }
                            let time = Time48::from_u64(now_secs() - if stale { 3600 } else { 0 });
                            ClientTransaction::request_with_fudge(
                                client.clone(),
                                &mut query,
                                time,
                                17,
                            )
                            .unwrap();
                            let query = query.finish();
                            assert_eq!(query.len(), request_len);
                            let full = extract_failed_response(
                                verify_tsig(
                                    &query,
                                    Some(key.clone()),
                                    crate::dns::message::ResponseLimit::STREAM,
                                )
                                .unwrap_err(),
                            );
                            assert_eq!(
                                Message::from_octets(full.as_slice())
                                    .unwrap()
                                    .header_counts()
                                    .qdcount(),
                                1
                            );
                            let limit = usize::from(edns.unwrap_or(512));
                            let response = extract_failed_response(
                                verify_tsig(
                                    &query,
                                    Some(key.clone()),
                                    crate::dns::message::ResponseLimit::udp(edns.unwrap_or(512)),
                                )
                                .unwrap_err(),
                            );
                            assert!(
                                response.len() <= limit,
                                "{algorithm:?}: {} > {limit}",
                                response.len()
                            );
                            let message = Message::from_octets(response.as_slice()).unwrap();
                            assert_eq!(message.header().id(), 8945);
                            assert_eq!(message.header().opcode(), opcode);
                            assert!(message.header().qr() && message.header().rd());
                            assert!(!message.header().tc());
                            assert_eq!(
                                message.header_counts().qdcount(),
                                u16::from(full.len() <= limit)
                            );
                            assert_eq!(
                                message.opt().map(|opt| opt.dnssec_ok()),
                                edns.map(|_| true)
                            );
                            let (rcode, error, signed_at, mac, other) =
                                extract_response_tsig(&response);
                            assert_eq!(rcode, Rcode::NOTAUTH);
                            assert_eq!(
                                error,
                                if stale {
                                    TsigRcode::BADTIME
                                } else {
                                    TsigRcode::BADTRUNC
                                }
                            );
                            assert_eq!(mac.len(), native);
                            if stale {
                                assert_eq!(signed_at, u64::from(time));
                            }
                            assert_eq!(other.len(), if stale { 6 } else { 0 });
                            assert_response_mac(&query, &response, algorithm);
                            let tsig =
                                ParsedTsig::parse(&Message::from_octets(query.as_slice()).unwrap())
                                    .unwrap()
                                    .unwrap();
                            let verifier = ResponseVerifier {
                                key: key.clone(),
                                request_mac: tsig.record.data().mac().to_vec(),
                            };
                            assert!(
                                verify_response(&verifier, &response)
                                    .unwrap_err()
                                    .is_authenticated()
                            );
                            let mut forged = response;
                            let index = forged.len() - if stale { 13 } else { 7 };
                            forged[index] ^= 1;
                            assert!(
                                !verify_response(&verifier, &forged)
                                    .unwrap_err()
                                    .is_authenticated()
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Build a signing-key fixture for the test.
pub(crate) fn test_key(algorithm: TsigAlgorithm) -> TsigKey {
    TsigKey {
        id: TsigKeyId::from(1),
        name: "update-key".to_string(),
        algorithm,
        secret: base64::engine::general_purpose::STANDARD.encode(SECRET),
        role_id: RoleId::from(1),
        created_at: Utc::now(),
    }
}

/// Return the current Unix time for TSIG test messages.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Encode a DNS name for a test wire message.
pub(crate) fn encode_name(name: &str) -> Vec<u8> {
    domain::base::Name::<Vec<u8>>::from_str(name)
        .unwrap()
        .as_slice()
        .to_vec()
}

/// Encode a TSIG timestamp as six big-endian bytes.
pub(crate) fn encode_u48(value: u64) -> [u8; 6] {
    let bytes = value.to_be_bytes();
    [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
}

/// Sign test message bytes with the selected HMAC algorithm.
pub(crate) fn hmac_sign(algorithm: TsigAlgorithm, data: &[u8]) -> Vec<u8> {
    let algorithm = match algorithm {
        TsigAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        TsigAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
        TsigAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
        TsigAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
    };
    hmac::sign(&hmac::Key::new(algorithm, SECRET), data)
        .as_ref()
        .to_vec()
}

/// Sign a minimal UPDATE with `update-key` (RFC 8945, Sections 4.3.2 and 4.3.3).
pub(crate) fn build_signed_update(algorithm: TsigAlgorithm, time_signed: u64) -> Vec<u8> {
    build_signed_update_with_tsig_fields(algorithm, time_signed, TsigRcode::NOERROR, &[])
}

/// Independently sign all TSIG variables, retaining arbitrary request Other Data.
fn build_signed_update_with_tsig_fields(
    algorithm: TsigAlgorithm,
    time_signed: u64,
    error: TsigRcode,
    other: &[u8],
) -> Vec<u8> {
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
    digest.extend_from_slice(&error.to_int().to_be_bytes());
    digest.extend_from_slice(&(other.len() as u16).to_be_bytes());
    digest.extend_from_slice(other);
    let mac = hmac_sign(algorithm, &digest);
    let mut rdata = algorithm_name;
    rdata.extend_from_slice(&encode_u48(time_signed));
    rdata.extend_from_slice(&300u16.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&base[..2]);
    rdata.extend_from_slice(&error.to_int().to_be_bytes());
    rdata.extend_from_slice(&(other.len() as u16).to_be_bytes());
    rdata.extend_from_slice(other);
    let mut message = base;
    message[10..12].copy_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&key_name);
    message.extend_from_slice(&Rtype::TSIG.to_int().to_be_bytes());
    message.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);
    message
}

/// Extract the response status and TSIG fields.
fn extract_response_tsig(response: &[u8]) -> (Rcode, TsigRcode, u64, Vec<u8>, Vec<u8>) {
    let msg = Message::from_octets(response).unwrap();
    let tsig_record = msg
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let data = tsig_record.data();

    (
        msg.header().rcode(),
        data.error(),
        u64::from(data.time_signed()),
        data.mac().to_vec(),
        data.other().to_vec(),
    )
}

/// Extract the DNS response from a TSIG verification failure.
fn extract_failed_response(err: TsigError) -> Vec<u8> {
    match err {
        TsigError::Rejected { response, .. } => response,
        other => panic!("expected TsigFailed, got {:?}", other),
    }
}

/// Check the response MAC against the request and actual wire fields.
pub(crate) fn assert_response_mac(query: &[u8], response: &[u8], algorithm: TsigAlgorithm) {
    let request = Message::from_octets(query).unwrap();
    let request_tsig = request
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let message = Message::from_octets(response).unwrap();
    let mut additional = message.additional().unwrap();
    let tsig_start = loop {
        let start = additional.pos();
        if additional.next().unwrap().unwrap().rtype() == Rtype::TSIG {
            break start;
        }
    };
    assert!(additional.next().is_none());
    let tsig = message
        .additional()
        .unwrap()
        .limit_to::<Tsig<_, _>>()
        .last()
        .unwrap()
        .unwrap();
    let data = tsig.data();
    let mut unsigned = response[..tsig_start].to_vec();
    unsigned[..2].copy_from_slice(&data.original_id().to_be_bytes());
    unsigned[10..12].copy_from_slice(&(message.header_counts().arcount() - 1).to_be_bytes());

    // RFC 8945, Section 4.3: sign the wire Other Data, including its six-byte time.
    let request_mac = request_tsig.data().mac();
    let mut digest = u16::try_from(request_mac.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    digest.extend_from_slice(request_mac);
    digest.extend_from_slice(&unsigned);
    tsig.owner().compose_canonical(&mut digest).unwrap();
    digest.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    digest.extend_from_slice(&0u32.to_be_bytes());
    data.algorithm().compose_canonical(&mut digest).unwrap();
    digest.extend_from_slice(&data.time_signed().into_octets());
    digest.extend_from_slice(&data.fudge().to_be_bytes());
    digest.extend_from_slice(&data.error().to_int().to_be_bytes());
    digest.extend_from_slice(&u16::try_from(data.other().len()).unwrap().to_be_bytes());
    digest.extend_from_slice(data.other());
    assert_eq!(data.mac(), &hmac_sign(algorithm, &digest));
}

/// Verify that `verify_tsig` accepts valid signatures for all algorithms.
#[test]
fn verify_tsig_accepts_valid_signatures_for_all_algorithms() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let query = build_signed_update(algorithm, now_secs());
        let key = test_key(algorithm).to_signing_key().unwrap();
        verify_tsig(
            &query,
            Some(key),
            crate::dns::message::ResponseLimit::STREAM,
        )
        .unwrap();
    }
}

/// Accept an upper-case algorithm name: the digest takes the canonical form
/// (RFC 8945, Section 4.3.3), so only the match has to fold (RFC 1035, Section 2.3.3).
#[test]
fn verify_tsig_accepts_mixed_case_algorithm_names() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let label = algorithm.as_str().as_bytes();
        let mut query = build_signed_update(algorithm, now_secs());
        let index = query
            .windows(label.len())
            .rposition(|window| window == label)
            .unwrap();
        query[index..index + label.len()].make_ascii_uppercase();
        assert!(matches!(
            request_signature(&query),
            RequestSignature::Key { .. }
        ));
        let key = test_key(algorithm).to_signing_key().unwrap();
        verify_tsig(
            &query,
            Some(key),
            crate::dns::message::ResponseLimit::STREAM,
        )
        .unwrap();
    }
}

/// Reject a bad MAC before considering the request's timestamp.
#[test]
fn verify_tsig_rejects_tampered_mac_with_badsig() {
    let key = test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    for offset in [-3600i64, 0, 3600] {
        let mut query = build_signed_update(
            TsigAlgorithm::HmacSha256,
            now_secs().checked_add_signed(offset).unwrap(),
        );
        // The MAC ends before original ID, error, and other-len (six bytes).
        let mac_end = query.len() - 7;
        query[mac_end] ^= 0xFF;
        let err = verify_tsig(
            &query,
            Some(key.clone()),
            crate::dns::message::ResponseLimit::STREAM,
        )
        .unwrap_err();
        // RFC 8945, Section 5.2: a failed MAC cannot produce signed BADTIME.
        let (rcode, error, _, mac, other) = extract_response_tsig(&extract_failed_response(err));
        assert_eq!(rcode, Rcode::NOTAUTH);
        assert_eq!(error, TsigRcode::BADSIG);
        assert!(mac.is_empty());
        assert!(other.is_empty());
    }
}

/// Verify that `verify_tsig` rejects original id mismatch with badsig.
#[test]
fn verify_tsig_rejects_original_id_mismatch_with_badsig() {
    let mut query = build_signed_update(TsigAlgorithm::HmacSha256, now_secs());
    // Flip the original ID (first two of the trailing six rdata bytes): the
    // MAC is computed over the original ID, so verification must fail.
    let original_id = query.len() - 6;
    query[original_id] ^= 0xFF;

    let key = test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let err = verify_tsig(
        &query,
        Some(key),
        crate::dns::message::ResponseLimit::STREAM,
    )
    .unwrap_err();

    let (rcode, error, _, _, _) = extract_response_tsig(&extract_failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADSIG);
}

/// Verify that `verify_tsig` rejects algorithm mismatch with badkey.
#[test]
fn verify_tsig_rejects_algorithm_mismatch_with_badkey() {
    let query = build_signed_update(TsigAlgorithm::HmacSha256, now_secs());

    let key = test_key(TsigAlgorithm::HmacSha512)
        .to_signing_key()
        .unwrap();
    let err = verify_tsig(
        &query,
        Some(key),
        crate::dns::message::ResponseLimit::STREAM,
    )
    .unwrap_err();

    let (rcode, error, _, mac, _) = extract_response_tsig(&extract_failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADKEY);
    assert!(mac.is_empty());
}

/// Verify that `verify_tsig` rejects unknown key with badkey.
#[test]
fn verify_tsig_rejects_unknown_key_with_badkey() {
    let query = build_signed_update(TsigAlgorithm::HmacSha256, now_secs());

    let err = verify_tsig(&query, None, crate::dns::message::ResponseLimit::STREAM).unwrap_err();

    let (rcode, error, _, mac, _) = extract_response_tsig(&extract_failed_response(err));
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADKEY);
    assert!(mac.is_empty());
}

/// Verify that `verify_tsig` rejects stale time with signed badtime.
#[test]
fn verify_tsig_rejects_stale_time_with_signed_badtime() {
    let stale = now_secs() - 3600;
    let query = build_signed_update(TsigAlgorithm::HmacSha256, stale);

    let key = test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let err = verify_tsig(
        &query,
        Some(key),
        crate::dns::message::ResponseLimit::STREAM,
    )
    .unwrap_err();

    // RFC 8945, Section 5.2.3: BADTIME responses are signed, echo the client's time,
    // and carry the server's time in other data.
    let response = extract_failed_response(err);
    let (rcode, error, time_signed, mac, other) = extract_response_tsig(&response);
    assert_eq!(rcode, Rcode::NOTAUTH);
    assert_eq!(error, TsigRcode::BADTIME);
    assert_eq!(time_signed, stale);
    assert_eq!(other.len(), 6);
    assert!(!mac.is_empty());
    assert_response_mac(&query, &response, TsigAlgorithm::HmacSha256);
}

/// Preserve EDNS and authenticate BADTIME across algorithms and request paths.
#[test]
fn badtime_response_preserves_edns() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let key = TsigKey {
            name: "UpDaTe-Key".to_string(),
            ..test_key(algorithm)
        }
        .to_signing_key()
        .unwrap();
        for offset in [-3600i64, 3600] {
            let signed_at = Time48::from_u64(now_secs().checked_add_signed(offset).unwrap());
            for opcode in [Opcode::QUERY, Opcode::UPDATE] {
                for edns in [None, Some((0, false)), Some((0, true)), Some((1, true))] {
                    let mut builder = MessageBuilder::new_vec();
                    builder.header_mut().set_id(8945);
                    builder.header_mut().set_opcode(opcode);
                    let mut question = builder.question();
                    question
                        .push((
                            Name::<Vec<u8>>::from_str("example.com.").unwrap(),
                            Rtype::SOA,
                        ))
                        .unwrap();
                    let mut additional = question.additional();
                    if let Some((version, dnssec_ok)) = edns {
                        additional
                            .opt(|opt| {
                                opt.set_udp_payload_size(4096);
                                opt.set_version(version);
                                opt.set_dnssec_ok(dnssec_ok);
                                Ok(())
                            })
                            .unwrap();
                    }
                    ClientTransaction::request_with_fudge(
                        key.clone(),
                        &mut additional,
                        signed_at,
                        17,
                    )
                    .unwrap();
                    let query = additional.finish();
                    let before = Time48::now();
                    let err = verify_tsig(
                        &query,
                        Some(key.clone()),
                        crate::dns::message::ResponseLimit::STREAM,
                    )
                    .unwrap_err();
                    let response = extract_failed_response(err);
                    let message = Message::from_octets(response.as_slice()).unwrap();
                    assert_eq!(message.header().id(), 8945);
                    assert_eq!(message.header().opcode(), opcode);
                    assert_eq!(message.header().rcode(), Rcode::NOTAUTH);
                    assert_eq!(
                        message.opt().map(|opt| opt.dnssec_ok()),
                        edns.map(|(_, do_bit)| do_bit)
                    );
                    let tsig = message
                        .additional()
                        .unwrap()
                        .limit_to::<Tsig<_, _>>()
                        .last()
                        .unwrap()
                        .unwrap();
                    assert_eq!(tsig.data().error(), TsigRcode::BADTIME);
                    assert_eq!(tsig.data().time_signed(), signed_at);
                    assert_eq!(tsig.data().fudge(), 17);
                    assert_eq!(tsig.data().other().len(), 6);
                    let server_time = tsig.data().other_time().unwrap();
                    assert!(server_time >= before && server_time <= Time48::now());
                    assert_response_mac(&query, &response, algorithm);
                }
            }
        }
    }
}

/// Check MAC and time before rejecting an authenticated truncation (RFC 8945, Section 5.2).
#[test]
fn truncated_requests_follow_validation_order() {
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        let key = test_key(algorithm).to_signing_key().unwrap();
        let native_len = key.as_ref().native_len();
        for (mac_len, edns) in [
            (native_len / 2, None),
            (native_len / 2, Some(false)),
            (native_len / 2, Some(true)),
            (native_len - 1, Some(true)),
            (native_len, Some(true)),
        ] {
            let client_key = Arc::new(
                Key::new(
                    key.as_ref().algorithm(),
                    SECRET,
                    key.as_ref().name().clone(),
                    None,
                    Some(mac_len),
                )
                .unwrap(),
            );
            for offset in [-3600i64, 0, 3600] {
                for corrupt in [false, true] {
                    let signed_at =
                        Time48::from_u64(now_secs().checked_add_signed(offset).unwrap());
                    let mut builder = MessageBuilder::new_vec();
                    builder.header_mut().set_id(8945);
                    let mut question = builder.question();
                    question
                        .push((
                            Name::<Vec<u8>>::from_str("example.com.").unwrap(),
                            Rtype::SOA,
                        ))
                        .unwrap();
                    let mut query = question.additional();
                    if let Some(dnssec_ok) = edns {
                        query
                            .opt(|opt| {
                                opt.set_udp_payload_size(1232);
                                opt.set_dnssec_ok(dnssec_ok);
                                Ok(())
                            })
                            .unwrap();
                    }
                    ClientTransaction::request_with_fudge(
                        client_key.clone(),
                        &mut query,
                        signed_at,
                        17,
                    )
                    .unwrap();
                    let mut query = query.finish();
                    if corrupt {
                        let mac_end = query.len() - 7;
                        query[mac_end] ^= 1;
                    }
                    let expected = if corrupt {
                        TsigRcode::BADSIG
                    } else if offset != 0 {
                        TsigRcode::BADTIME
                    } else if mac_len != native_len {
                        TsigRcode::BADTRUNC
                    } else {
                        TsigRcode::NOERROR
                    };
                    let before = now_secs();
                    let result = verify_tsig(
                        &query,
                        Some(key.clone()),
                        crate::dns::message::ResponseLimit::STREAM,
                    );
                    if expected == TsigRcode::NOERROR {
                        result.unwrap();
                    } else {
                        let err = result.unwrap_err();
                        assert!(
                            matches!(&err, TsigError::Rejected { rcode, .. } if *rcode == expected)
                        );
                        let response = extract_failed_response(err);
                        let (rcode, error, time_signed, mac, other) =
                            extract_response_tsig(&response);
                        assert_eq!(rcode, Rcode::NOTAUTH);
                        assert_eq!(
                            error, expected,
                            "{algorithm:?}, MAC {mac_len}, offset {offset}, corrupt {corrupt}"
                        );
                        assert_eq!(
                            Message::from_octets(response.as_slice())
                                .unwrap()
                                .opt()
                                .map(|opt| opt.dnssec_ok()),
                            edns
                        );
                        if corrupt {
                            assert!(mac.is_empty());
                            assert!(other.is_empty());
                        } else {
                            assert_eq!(mac.len(), native_len);
                            assert_response_mac(&query, &response, algorithm);
                            if expected == TsigRcode::BADTIME {
                                assert_eq!(time_signed, u64::from(signed_at));
                                assert_eq!(other.len(), 6);
                            } else {
                                assert!(time_signed >= before && time_signed <= now_secs());
                                assert!(other.is_empty());
                            }
                        }
                    }
                    let unknown_key = extract_failed_response(
                        verify_tsig(&query, None, crate::dns::message::ResponseLimit::STREAM)
                            .unwrap_err(),
                    );
                    let (_, error, _, mac, _) = extract_response_tsig(&unknown_key);
                    assert_eq!(error, TsigRcode::BADKEY);
                    assert!(mac.is_empty());
                }
            }
        }
    }
}

/// Keep the outbound full-length policy after authenticating response MACs.
#[test]
fn outbound_responses_require_full_length_macs() {
    let key = test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    for mac_len in [16, 31, 32] {
        let server_key = Arc::new(
            Key::new(
                Algorithm::Sha256,
                SECRET,
                key.as_ref().name().clone(),
                None,
                Some(mac_len),
            )
            .unwrap(),
        );
        let mut question = MessageBuilder::new_vec().question();
        question
            .push((
                Name::<Vec<u8>>::from_str("example.com.").unwrap(),
                Rtype::SOA,
            ))
            .unwrap();
        let mut query = question.additional();
        let verifier = sign_request(&mut query, key.clone()).unwrap();
        let mut query = Message::from_octets(query.finish()).unwrap();
        let server = ServerTransaction::request(&server_key, &mut query, Time48::now())
            .unwrap()
            .unwrap();
        let mut response = MessageBuilder::new_vec()
            .start_answer(&query, Rcode::NOERROR)
            .unwrap()
            .additional();
        server.answer(&mut response, Time48::now()).unwrap();
        let mut response = response.finish();
        let result = verify_response(&verifier, &response);
        if mac_len == 32 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(VerifyResponseError::TruncatedMac)));
        }
        let mac_end = response.len() - 7;
        response[mac_end] ^= 1;
        assert!(matches!(
            verify_response(&verifier, &response),
            Err(VerifyResponseError::Rejected(_))
        ));
    }
}

/// Verify that the TSIG reservation covers the longest key name and MAC.
#[test]
fn reserved_tsig_size_covers_maximum_key_name() {
    // The longest name a key can carry, under the algorithm with the widest MAC.
    let name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let key = TsigKey {
        name,
        algorithm: TsigAlgorithm::HmacSha512,
        ..test_key(TsigAlgorithm::HmacSha512)
    }
    .to_signing_key()
    .unwrap();

    let composed = usize::from(key.as_ref().compose_len());
    assert!(
        composed <= MAX_TSIG_RECORD,
        "a {composed}-byte TSIG record does not fit the {MAX_TSIG_RECORD} bytes reserved for one"
    );
}

/// Keep malformed TSIG requests from being treated as unsigned.
#[test]
fn tsig_parser_rejects_unparseable_signature() {
    let signed = build_signed_update(TsigAlgorithm::HmacSha256, now_secs());
    assert!(matches!(
        request_signature(&signed),
        RequestSignature::Key { name, fudge: 300 } if name == "update-key"
    ));

    // Malformed TSIG must not fall through to address-based authorization.
    let mut empty_rdata = minimal_update_with_ztype(6);
    empty_rdata[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    empty_rdata.extend_from_slice(&encode_name("update-key"));
    empty_rdata.extend_from_slice(&Rtype::TSIG.to_int().to_be_bytes());
    empty_rdata.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    empty_rdata.extend_from_slice(&0u32.to_be_bytes()); // TTL
    empty_rdata.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    assert!(matches!(
        request_signature(&empty_rdata),
        RequestSignature::Malformed
    ));

    // An overrun prevents establishing whether more records follow.
    let mut overrun = empty_rdata.clone();
    let rdlength_at = overrun.len() - 2;
    overrun[rdlength_at..].copy_from_slice(&8u16.to_be_bytes());
    assert!(matches!(
        request_signature(&overrun),
        RequestSignature::Malformed
    ));

    assert!(matches!(
        request_signature(&minimal_update_with_ztype(6)),
        RequestSignature::Absent
    ));
}

/// The signed update with its TSIG MAC replaced by `mac_len` zero octets; the
/// digest does not verify, which the structure checks never reach.
fn update_with_mac_of(mac_len: usize) -> Vec<u8> {
    let key_name = encode_name("update-key");
    let algorithm_name = encode_name(TsigAlgorithm::HmacSha256.as_str());
    let mac = vec![0u8; mac_len];

    let mut message = minimal_update_with_ztype(6);
    message[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
    message.extend_from_slice(&key_name);
    message.extend_from_slice(&Rtype::TSIG.to_int().to_be_bytes());
    message.extend_from_slice(&Class::ANY.to_int().to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes()); // TTL
    let rdlen = algorithm_name.len() + 6 + 2 + 2 + mac.len() + 2 + 2 + 2;
    message.extend_from_slice(&(rdlen as u16).to_be_bytes());
    message.extend_from_slice(&algorithm_name);
    message.extend_from_slice(&encode_u48(now_secs()));
    message.extend_from_slice(&300u16.to_be_bytes());
    message.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    message.extend_from_slice(&mac);
    message.extend_from_slice(&[0x12, 0x34]); // original ID
    message.extend_from_slice(&0u16.to_be_bytes()); // error
    message.extend_from_slice(&0u16.to_be_bytes()); // other len
    message
}

/// Verify malformed TSIG placement and MAC lengths while admitting valid truncation
/// (RFC 8945, Sections 5.2 and 5.2.2.1).
#[test]
fn tsig_parser_rejects_invalid_section_5_2_envelopes() {
    let signed = build_signed_update(TsigAlgorithm::HmacSha256, now_secs());

    // An A record after the TSIG: the TSIG is no longer the last record.
    let mut not_last = signed.clone();
    not_last[10..12].copy_from_slice(&2u16.to_be_bytes());
    not_last.extend_from_slice(&encode_name("host.example.com"));
    not_last.extend_from_slice(&Rtype::A.to_int().to_be_bytes());
    not_last.extend_from_slice(&Class::IN.to_int().to_be_bytes());
    not_last.extend_from_slice(&0u32.to_be_bytes());
    not_last.extend_from_slice(&4u16.to_be_bytes());
    not_last.extend_from_slice(&[192, 0, 2, 1]);
    assert!(matches!(
        request_signature(&not_last),
        RequestSignature::Malformed
    ));

    // The TSIG record twice over.
    let base_len = minimal_update_with_ztype(6).len();
    let mut doubled = signed;
    doubled[10..12].copy_from_slice(&2u16.to_be_bytes());
    doubled.extend_from_within(base_len..);
    assert!(matches!(
        request_signature(&doubled),
        RequestSignature::Malformed
    ));

    // SHA-256 allows 16..=32 bytes structurally; key validation may still
    // reject 16-byte truncation with BADTRUNC.
    for (mac_len, malformed) in [(4, true), (40, true), (16, false), (32, false)] {
        let signature = request_signature(&update_with_mac_of(mac_len));
        assert_eq!(
            matches!(signature, RequestSignature::Malformed),
            malformed,
            "mac of {mac_len}: {signature:?}"
        );
    }
}

/// TSIG belongs only in Additional, with CLASS ANY and TTL zero (RFC 8945, Section 4.2).
#[test]
fn tsig_envelope_rejects_wrong_class_ttl_and_sections() {
    let wire = build_signed_update(TsigAlgorithm::HmacSha256, now_secs());
    let start = minimal_update_with_ztype(6).len();
    let class = start + encode_name("update-key").len() + 2;
    for offset in [class + 1, class + 5] {
        let mut malformed = wire.clone();
        malformed[offset] = 1;
        assert!(matches!(
            request_signature(&malformed),
            RequestSignature::Malformed
        ));
    }
    for count in [6, 8] {
        let mut malformed = wire.clone();
        malformed[count..count + 2].copy_from_slice(&1u16.to_be_bytes());
        malformed[10..12].fill(0);
        assert!(matches!(
            request_signature(&malformed),
            RequestSignature::Malformed
        ));
    }
}
