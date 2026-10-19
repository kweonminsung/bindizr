use std::{net::SocketAddr, time::Duration};

use bindizr_core::{
    dns::{
        message::{Name, Opcode, Rtype},
        name::ZoneName,
        query::{build_question, validate_notify_response},
        tsig::{TsigSigningKey, sign_request, verify_response},
    },
    metrics::NotifyResult,
};
use thiserror::Error;

use super::{ExchangeMessageError, ResolveAddressError};
use crate::{
    Context, error::ServiceError, model::secondary::Secondary, secondary,
    types::CheckNotifyResponse,
};

/// Why one NOTIFY to one address was not acknowledged.
#[derive(Debug, Error)]
pub enum SendNotifyError {
    #[error(transparent)]
    Sign(#[from] bindizr_core::dns::tsig::SignRequestError),
    #[error(transparent)]
    Exchange(#[from] ExchangeMessageError),
    #[error(transparent)]
    Verify(#[from] bindizr_core::dns::tsig::VerifyResponseError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ParseResponseError),
    #[error("NOTIFY task failed: {0}")]
    TaskFailed(#[source] tokio::task::JoinError),
}

/// NOTIFY for a zone did not reach every address of its secondaries.
#[derive(Debug, Error)]
pub enum NotifyZoneError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// The addresses that failed, each with the text its report carries.
    #[error("NOTIFY failed for zone {zone_name} ({})", failures.iter().map(|(address, error)| format!("{address}: {error}")).collect::<Vec<_>>().join("; "))]
    Undelivered {
        zone_name: String,
        failures: Vec<(String, String)>,
    },
}

/// Sends DNS NOTIFY to every enabled secondary for one zone. Which
/// zones to notify is the caller's decision.
pub(crate) async fn send_zone_notify(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<(), NotifyZoneError> {
    log::info!("Sending NOTIFY for zone: {}", zone_name);

    let reports = send_notify_to_secondaries(cx, zone_name).await?;
    if reports.is_empty() {
        log::info!("No enabled secondaries");
        return Ok(());
    }

    let failures: Vec<(String, String)> = reports
        .into_iter()
        .filter_map(|report| report.error.map(|error| (report.address, error)))
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(NotifyZoneError::Undelivered {
            zone_name: zone_name.to_string(),
            failures,
        })
    }
}

/// Send NOTIFY for a zone to every enabled secondary, one outcome per
/// address; none yields an empty list.
pub async fn send_notify_to_secondaries(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    let secondaries = secondary::list_enabled(cx).await?;
    send_notify(cx, zone_name, secondaries).await
}

/// Send NOTIFY for a zone to every resolved address of one secondary, signed
/// with its NOTIFY key when it has one; one outcome per address.
pub async fn send_notify_to_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    send_notify(cx, zone_name, vec![secondary.clone()]).await
}

/// Send NOTIFY for a zone to every address of each secondary, signed with its
/// NOTIFY key when it has one; one outcome per address.
async fn send_notify(
    cx: &Context,
    zone_name: &ZoneName,
    secondaries: Vec<Secondary>,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    // The zone name is a stored row, so one that does not parse is the
    // server's fault.
    let qname = zone_name
        .to_wire_name()
        .map_err(|e| ServiceError::internal_with_source(format!("invalid zone name: {}", e), e))?;
    let timeout = cx.config().dns.notify.timeout();
    let retries = cx.config().dns.notify.retries;

    // Send concurrently so an unresponsive secondary cannot delay the others.
    let mut reports = Vec::new();
    let mut tasks = Vec::with_capacity(secondaries.len());
    for secondary in secondaries {
        let tsig_key = match secondary::find_notify_signing_key(cx, &secondary).await {
            Ok(tsig_key) => tsig_key,
            Err(e) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                reports.push(CheckNotifyResponse {
                    address: secondary.address.to_string(),
                    error: Some(e.to_string()),
                });
                continue;
            }
        };
        let qname = qname.clone();
        tasks.push((
            secondary.address.clone(),
            tokio::spawn(async move {
                let addrs = super::resolve_address_entry(&secondary.address, timeout).await?;
                let mut outcomes = Vec::with_capacity(addrs.len());
                for addr in addrs {
                    let result =
                        send_notify_to_server(&qname, addr, timeout, retries, tsig_key.as_ref())
                            .await;
                    outcomes.push((addr, result));
                }
                Ok::<_, ResolveAddressError>(outcomes)
            }),
        ));
    }

    for (address, task) in tasks {
        let outcomes = match task.await {
            Ok(Ok(outcomes)) => outcomes,
            Ok(Err(e)) => {
                cx.metrics().track_notify(NotifyResult::ResolveFailed);
                reports.push(CheckNotifyResponse {
                    address: address.to_string(),
                    error: Some(format!("failed to resolve: {}", e)),
                });
                continue;
            }
            Err(e) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                reports.push(CheckNotifyResponse {
                    address: address.to_string(),
                    error: Some(SendNotifyError::TaskFailed(e).to_string()),
                });
                continue;
            }
        };
        for (addr, result) in outcomes {
            let error = match result {
                Ok(()) => {
                    log::info!("NOTIFY sent successfully to {}", addr);
                    cx.metrics().track_notify(NotifyResult::Ok);
                    None
                }
                Err(e) => {
                    log::error!("Failed to send NOTIFY to {}: {}", addr, e);
                    cx.metrics().track_notify(NotifyResult::Failed);
                    Some(e.to_string())
                }
            };
            reports.push(CheckNotifyResponse {
                address: addr.to_string(),
                error,
            });
        }
    }
    Ok(reports)
}

/// Sends a NOTIFY to one server, retrying up to the configured limit; with
/// `key`, each attempt is signed and its answer checked.
async fn send_notify_to_server(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
    retries: u32,
    tsig_key: Option<&TsigSigningKey>,
) -> Result<(), SendNotifyError> {
    let attempts = retries.saturating_add(1);
    let mut attempt = 1;

    loop {
        match send_notify_to_server_once(qname, server_addr, timeout, tsig_key).await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < attempts => {
                attempt += 1;
                log::info!(
                    "Retrying NOTIFY to {} ({}/{}) after error: {}",
                    server_addr,
                    attempt,
                    attempts,
                    e
                );
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send one NOTIFY attempt and validate the server's response, its
/// signature before its RCODE, so a rejected key is reported as such.
async fn send_notify_to_server_once(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
    tsig_key: Option<&TsigSigningKey>,
) -> Result<(), SendNotifyError> {
    let (query_id, mut builder) =
        build_question(Opcode::NOTIFY, true, false, qname, Rtype::SOA, None);
    let signer = match tsig_key {
        Some(tsig_key) => Some(sign_request(&mut builder, tsig_key.clone())?),
        None => None,
    };
    let notify_message = builder.finish();

    let (received, response) = super::exchange_over_udp_checked(
        server_addr,
        timeout,
        &notify_message,
        "NOTIFY",
        |response| {
            signer
                .as_ref()
                .is_none_or(|signer| match verify_response(signer, response) {
                    Ok(()) => true,
                    Err(error) => error.is_authenticated(),
                })
        },
    )
    .await?;

    log::info!(
        "NOTIFY message sent to {} ({} bytes, signed={})",
        server_addr,
        notify_message.len(),
        signer.is_some()
    );

    if let Some(signer) = &signer {
        verify_response(signer, &response[..received])?;
    }
    validate_notify_response(query_id, qname, &response[..received])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bindizr_core::dns::message::Name;

    use super::*;
    use crate::dns_client::ds::tests::encode_name;

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

    /// Build the test zone or its DNS name.
    fn zone() -> Name<Vec<u8>> {
        Name::from_str("example.com").unwrap()
    }

    /// Encode an independent HMAC-SHA256 acknowledgement.
    fn signed_ack(request: &[u8], error: u16) -> Vec<u8> {
        use ring::hmac;
        let id = u16::from_be_bytes([request[0], request[1]]);
        let mut response =
            build_notify_response(id, if error == 0 { 0xa000 } else { 0xa009 }, "example.com");
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
                send_notify_to_server_once(&zone(), address, Duration::from_secs(1), Some(&key)),
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
            send_notify_to_server_once(&zone(), address, Duration::from_millis(80), Some(&key)),
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
}
