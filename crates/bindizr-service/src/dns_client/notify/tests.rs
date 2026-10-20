use std::str::FromStr;

use bindizr_core::dns::message::Name;

use super::*;
use crate::dns_client::ds::tests::encode_name;

/// Only oversized signed queries need EDNS; their signature includes the OPT.
#[tokio::test]
async fn signed_notify_advertises_edns_for_long_names() {
    use base64::Engine;
    use bindizr_core::{
        dns::{
            message::{Edns, Keepalive, ParsedQuery},
            tsig::{TransferSigner, verify_tsig},
        },
        model::{
            role::RoleId,
            tsig_key::{TsigAlgorithm, TsigKey, TsigKeyId},
        },
    };
    let long_name = |c: &str| {
        format!(
            "{}.{}.{}.{}",
            c.repeat(63),
            c.repeat(63),
            c.repeat(63),
            c.repeat(61)
        )
    };
    for algorithm in [
        TsigAlgorithm::HmacSha1,
        TsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512,
    ] {
        for long in [false, true] {
            let qname = Name::<Vec<u8>>::from_str(&if long {
                long_name("z")
            } else {
                "example.com".into()
            })
            .unwrap();
            let key = TsigKey {
                id: TsigKeyId::from(1),
                name: if long {
                    long_name("k")
                } else {
                    "notify-key".into()
                },
                algorithm,
                secret: base64::engine::general_purpose::STANDARD.encode([1u8; 64]),
                role_id: RoleId::from(1),
                created_at: chrono::Utc::now(),
            }
            .to_signing_key()
            .unwrap();
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let server_key = key.clone();
            let capture = tokio::spawn(async move {
                let mut buf = [0; 4096];
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let query = ParsedQuery::parse(&buf[..len], Keepalive::None).unwrap();
                let mut signer: TransferSigner =
                    verify_tsig(&buf[..len], Some(server_key)).unwrap().into();
                let response = query
                    .build_signed_error_response(OptRcode::NOERROR, None, Some(&mut signer))
                    .unwrap();
                socket.send_to(&response, peer).await.unwrap();
                (len, query.edns)
            });
            send_notify_to_server(&qname, addr, Duration::from_secs(1), 0, Some(&key))
                .await
                .unwrap();
            let (len, edns) = capture.await.unwrap();
            assert_eq!(edns != Edns::Absent, long);
            assert!(len <= if long { 1232 } else { 512 });
            if long {
                assert!(len > 512);
            }
        }
    }
}

/// A NOTIFY response with `flags`, echoing a SOA question for `qname`.
fn build_notify_response(query_id: u16, flags: u16, qname: &str) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query_id.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    encode_name(qname, &mut response);
    response.extend_from_slice(&6u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response
}

/// Return the test zone's wire name.
fn zone() -> Name<Vec<u8>> {
    Name::from_str("example.com").unwrap()
}

/// Encode an independent HMAC-SHA256 acknowledgement.
fn signed_ack(request: &[u8], error: u16, rcode: u16) -> Vec<u8> {
    use ring::hmac;
    let id = u16::from_be_bytes([request[0], request[1]]);
    let mut response = build_notify_response(
        id,
        if error == 0 { 0xa000 | rcode } else { 0xa009 },
        "example.com",
    );
    let mut owner = Vec::new();
    encode_name("notify-key", &mut owner);
    let mut algorithm = Vec::new();
    encode_name("hmac-sha256", &mut algorithm);
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let time = &seconds.to_be_bytes()[2..];
    let mut variables = owner.clone();
    variables.extend_from_slice(&[0, 255, 0, 0, 0, 0]);
    variables.extend_from_slice(&algorithm);
    variables.extend_from_slice(time);
    let other = if error == 18 { time } else { &[] };
    variables.extend_from_slice(&[1, 44]);
    variables.extend_from_slice(&error.to_be_bytes());
    variables.extend_from_slice(&(other.len() as u16).to_be_bytes());
    variables.extend_from_slice(other);
    let mut digest = 32u16.to_be_bytes().to_vec();
    digest.extend_from_slice(&request[request.len() - 38..request.len() - 6]);
    digest.extend_from_slice(&response);
    digest.extend_from_slice(&variables);
    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, b"notify-test-secret-at-least-32-bytes"),
        &digest,
    );
    let mut rdata = algorithm;
    rdata.extend_from_slice(time);
    rdata.extend_from_slice(&[1, 44, 0, 32]);
    rdata.extend_from_slice(mac.as_ref());
    rdata.extend_from_slice(&id.to_be_bytes());
    rdata.extend_from_slice(&error.to_be_bytes());
    rdata.extend_from_slice(&(other.len() as u16).to_be_bytes());
    rdata.extend_from_slice(other);
    response[10..12].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&owner);
    response.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
    response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&rdata);
    response
}

/// Ignore untrusted replies; accept valid ACKs or authenticated errors.
#[tokio::test]
async fn signed_notify_waits_for_valid_ack_after_untrusted_datagrams() {
    use base64::Engine;
    use bindizr_core::model::{
        role::RoleId,
        tsig_key::{TsigAlgorithm, TsigKey, TsigKeyId},
    };
    use tokio::net::UdpSocket;
    let key = TsigKey {
        id: TsigKeyId::from(1),
        name: "notify-key".into(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret: base64::engine::general_purpose::STANDARD
            .encode(b"notify-test-secret-at-least-32-bytes"),
        role_id: RoleId::from(1),
        created_at: chrono::Utc::now(),
    }
    .to_signing_key()
    .unwrap();
    for noise in ["bad-mac", "unsigned", "notauth", "badtime", "badtrunc"] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut request = [0; 4096];
            let (len, peer) = socket.recv_from(&mut request).await.unwrap();
            let request = &request[..len];
            let response = signed_ack(
                request,
                match noise {
                    "badtime" => 18,
                    "badtrunc" => 22,
                    _ => 0,
                },
                0,
            );
            if matches!(noise, "badtime" | "badtrunc") {
                socket.send_to(&response, peer).await.unwrap();
                return;
            }
            let id = u16::from_be_bytes([request[0], request[1]]);
            let invalid = match noise {
                "bad-mac" => {
                    let mut invalid = response.clone();
                    let index = invalid.len() - 7;
                    invalid[index] ^= 1;
                    invalid
                }
                "unsigned" => build_notify_response(id, 0xa000, "example.com"),
                _ => build_notify_response(id, 0xa009, "example.com"),
            };
            socket.send_to(&invalid, peer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket.send_to(&response, peer).await.unwrap();
        });
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            send_notify_to_server(&zone(), address, Duration::from_secs(1), 0, Some(&key)),
        )
        .await
        .unwrap();
        if matches!(noise, "badtime" | "badtrunc") {
            assert!(
                matches!(result, Err(SendNotifyError::Verify(error)) if error.is_authenticated())
            );
        } else {
            result.unwrap();
        }
        server.await.unwrap();
    }
}

/// Any matching reply ends the transaction after one attempt (RFC 1996,
/// Sections 3.6 and 4.8); only silence retains the configured retries.
#[tokio::test]
async fn notify_completes_on_any_reply_and_retries_silence() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::net::UdpSocket;

    for (rcode, attempts, ok) in [
        (Some(0), 1, true),
        (Some(4), 1, true),
        (Some(2), 1, false),
        (None, 3, false),
    ] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let received = count.clone();
        let server = tokio::spawn(async move {
            let mut request = [0; 4096];
            loop {
                let (_, peer) = socket.recv_from(&mut request).await.unwrap();
                received.fetch_add(1, Ordering::SeqCst);
                if let Some(code) = rcode {
                    let id = u16::from_be_bytes([request[0], request[1]]);
                    socket
                        .send_to(
                            &build_notify_response(id, 0xa000 | code, "example.com"),
                            peer,
                        )
                        .await
                        .unwrap();
                }
            }
        });
        let result =
            send_notify_to_server(&zone(), address, Duration::from_millis(50), 2, None).await;
        server.abort();
        assert_eq!(count.load(Ordering::SeqCst), attempts, "{rcode:?}");
        assert_eq!(result.is_ok(), ok, "{rcode:?}: {result:?}");
    }
}

/// Only a valid signature can make NOTIMP complete a signed transaction.
#[tokio::test]
async fn signed_notify_requires_authenticated_notimp_before_completing() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use base64::Engine;
    use bindizr_core::model::{
        role::RoleId,
        tsig_key::{TsigAlgorithm, TsigKey, TsigKeyId},
    };
    use tokio::net::UdpSocket;

    let key = TsigKey {
        id: TsigKeyId::from(1),
        name: "notify-key".into(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret: base64::engine::general_purpose::STANDARD
            .encode(b"notify-test-secret-at-least-32-bytes"),
        role_id: RoleId::from(1),
        created_at: chrono::Utc::now(),
    }
    .to_signing_key()
    .unwrap();
    for (mode, expected) in [("valid", 1), ("unsigned", 3), ("bad-mac", 3)] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let received = count.clone();
        let server = tokio::spawn(async move {
            let mut request = [0; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut request).await.unwrap();
                received.fetch_add(1, Ordering::SeqCst);
                let mut response = signed_ack(&request[..len], 0, 4);
                match mode {
                    "unsigned" => {
                        let id = u16::from_be_bytes([request[0], request[1]]);
                        response = build_notify_response(id, 0xa004, "example.com");
                    }
                    "bad-mac" => {
                        let index = response.len() - 7;
                        response[index] ^= 1;
                    }
                    _ => {}
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let result =
            send_notify_to_server(&zone(), address, Duration::from_millis(50), 2, Some(&key)).await;
        server.abort();
        assert_eq!(count.load(Ordering::SeqCst), expected, "{mode}");
        assert_eq!(result.is_ok(), mode == "valid", "{mode}: {result:?}");
    }
}

/// Unsigned replies cannot extend the NOTIFY deadline.
#[tokio::test]
async fn signed_notify_times_out_under_unsigned_response_flood() {
    use base64::Engine;
    use bindizr_core::model::{
        role::RoleId,
        tsig_key::{TsigAlgorithm, TsigKey, TsigKeyId},
    };
    use tokio::net::UdpSocket;
    let key = TsigKey {
        id: TsigKeyId::from(1),
        name: "notify-key".into(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret: base64::engine::general_purpose::STANDARD
            .encode(b"notify-test-secret-at-least-32-bytes"),
        role_id: RoleId::from(1),
        created_at: chrono::Utc::now(),
    }
    .to_signing_key()
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut request = [0; 4096];
        let (len, peer) = socket.recv_from(&mut request).await.unwrap();
        assert!(len > 12);
        let id = u16::from_be_bytes([request[0], request[1]]);
        let response = build_notify_response(id, 0xa000, "example.com");
        loop {
            socket.send_to(&response, peer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        send_notify_to_server(&zone(), address, Duration::from_millis(80), 0, Some(&key)),
    )
    .await
    .unwrap();
    server.abort();
    assert!(matches!(
        result,
        Err(SendNotifyError::Exchange(
            ExchangeMessageError::ResponseTimedOut { .. }
        ))
    ));
}

/// Verify that `validate_notify_response` accepts matching noerror response.
#[test]
fn validate_notify_response_accepts_matching_noerror_response() {
    // 0xa000 = QR set + opcode NOTIFY, NOERROR.
    let response = build_notify_response(1234, 0xa000, "example.com");

    assert!(validate_notify_response(1234, &zone(), &response).is_ok());
}

/// Verify that `validate_notify_response` rejects id mismatch.
#[test]
fn validate_notify_response_rejects_id_mismatch() {
    let response = build_notify_response(1234, 0xa000, "example.com");

    let err = validate_notify_response(5678, &zone(), &response).unwrap_err();

    assert!(err.to_string().contains("ID mismatch"));
}

/// Verify that `validate_notify_response` rejects error rcode.
#[test]
fn validate_notify_response_rejects_error_rcode() {
    // 0xa005 adds RCODE 5 (REFUSED).
    let response = build_notify_response(1234, 0xa005, "example.com");

    let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

    assert!(err.to_string().contains("RCODE 5"));
}

/// Verify that `validate_notify_response` reports the RCODE of a refusal
/// that carries no question.
#[test]
fn validate_notify_response_reports_rcode_without_question() {
    // NSD 4.6 answers NOTIFY for a zone it does not serve with NOTAUTH
    // (RCODE 9) and an empty question section.
    let mut response = build_notify_response(1234, 0xa009, "example.com");
    response.truncate(12);
    response[4..6].copy_from_slice(&0u16.to_be_bytes());

    let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

    assert!(err.to_string().contains("RCODE 9"), "{err}");
}

/// Verify that `validate_notify_response` rejects another question.
#[test]
fn validate_notify_response_rejects_another_question() {
    let response = build_notify_response(1234, 0xa000, "other.com");

    let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

    assert!(err.to_string().contains("another question"), "{err}");
}
