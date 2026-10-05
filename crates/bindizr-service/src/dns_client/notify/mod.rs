use std::{net::SocketAddr, time::Duration};

use bindizr_core::{
    dns::{
        message::{Name, Opcode, Rtype},
        name::ZoneName,
        query::{question_builder, validate_notify_response},
        tsig::{TsigSigningKey, sign_request, verify_response},
    },
    metrics::NotifyResult,
};
use thiserror::Error;

use super::{ExchangeError, ResolveAddressError};
use crate::{
    Context, error::ServiceError, model::secondary::Secondary, secondary,
    types::NotifyCheckResponse,
};

/// Why one NOTIFY to one address was not acknowledged.
#[derive(Debug, Error)]
pub enum SendNotifyError {
    #[error(transparent)]
    Sign(#[from] bindizr_core::dns::tsig::SignRequestError),
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
    #[error(transparent)]
    Verify(#[from] bindizr_core::dns::tsig::VerifyAnswerError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ReadResponseError),
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
) -> Result<Vec<NotifyCheckResponse>, ServiceError> {
    let secondaries = secondary::list_enabled(cx).await?;
    send_notify(cx, zone_name, secondaries).await
}

/// Send NOTIFY for a zone to every resolved address of one secondary, signed
/// with its NOTIFY key when it has one; one outcome per address.
pub async fn send_notify_to_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
) -> Result<Vec<NotifyCheckResponse>, ServiceError> {
    send_notify(cx, zone_name, vec![secondary.clone()]).await
}

/// Send NOTIFY for a zone to every address of each secondary, signed with its
/// NOTIFY key when it has one; one outcome per address.
async fn send_notify(
    cx: &Context,
    zone_name: &ZoneName,
    secondaries: Vec<Secondary>,
) -> Result<Vec<NotifyCheckResponse>, ServiceError> {
    // The zone name is a stored row, so one that does not parse is the
    // server's fault.
    let qname = zone_name
        .to_wire_name()
        .map_err(|e| ServiceError::internal_with_source(format!("invalid zone name: {}", e), e))?;
    let timeout = cx.config().dns.notify.timeout();
    let retries = cx.config().dns.notify.retries;

    // A secondary that never answers must cost its own timeouts, not the
    // others': each sends on a task of its own, the key lookup and metrics
    // stay on this one.
    let mut reports = Vec::new();
    let mut tasks = Vec::with_capacity(secondaries.len());
    for secondary in secondaries {
        let key = match secondary::notify_signing_key(cx, &secondary).await {
            Ok(key) => key,
            Err(e) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                reports.push(NotifyCheckResponse {
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
                        send_notify_to_server(&qname, addr, timeout, retries, key.as_ref()).await;
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
                reports.push(NotifyCheckResponse {
                    address: address.to_string(),
                    error: Some(format!("failed to resolve: {}", e)),
                });
                continue;
            }
            Err(e) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                reports.push(NotifyCheckResponse {
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
            reports.push(NotifyCheckResponse {
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
    key: Option<&TsigSigningKey>,
) -> Result<(), SendNotifyError> {
    let attempts = retries.saturating_add(1);
    let mut attempt = 1;

    loop {
        match send_notify_to_server_once(qname, server_addr, timeout, key).await {
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
    key: Option<&TsigSigningKey>,
) -> Result<(), SendNotifyError> {
    let (query_id, mut builder) = question_builder(Opcode::NOTIFY, true, false, qname, Rtype::SOA);
    let signer = match key {
        Some(key) => Some(sign_request(&mut builder, key.clone())?),
        None => None,
    };
    let notify_message = builder.finish();

    let (received, response) =
        super::exchange_over_udp(server_addr, timeout, &notify_message, "NOTIFY").await?;

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
    fn notify_response(query_id: u16, flags: u16, qname: &str) -> Vec<u8> {
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

    /// Verify that `validate_notify_response` accepts matching noerror response.
    #[test]
    fn validate_notify_response_accepts_matching_noerror_response() {
        // 0xa000 = QR set + opcode NOTIFY, NOERROR.
        let response = notify_response(1234, 0xa000, "example.com");

        assert!(validate_notify_response(1234, &zone(), &response).is_ok());
    }

    /// Verify that `validate_notify_response` rejects id mismatch.
    #[test]
    fn validate_notify_response_rejects_id_mismatch() {
        let response = notify_response(1234, 0xa000, "example.com");

        let err = validate_notify_response(5678, &zone(), &response).unwrap_err();

        assert!(err.to_string().contains("ID mismatch"));
    }

    /// Verify that `validate_notify_response` rejects error rcode.
    #[test]
    fn validate_notify_response_rejects_error_rcode() {
        // 0xa005 adds RCODE 5 (REFUSED).
        let response = notify_response(1234, 0xa005, "example.com");

        let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

        assert!(err.to_string().contains("RCODE 5"));
    }

    /// Verify that `validate_notify_response` reports the RCODE of a refusal
    /// that carries no question.
    #[test]
    fn validate_notify_response_reports_rcode_without_question() {
        // NSD 4.6 answers NOTIFY for a zone it does not serve with NOTAUTH
        // (RCODE 9) and an empty question section.
        let mut response = notify_response(1234, 0xa009, "example.com");
        response.truncate(12);
        response[4..6].copy_from_slice(&0u16.to_be_bytes());

        let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

        assert!(err.to_string().contains("RCODE 9"), "{err}");
    }

    /// Verify that `validate_notify_response` rejects another question.
    #[test]
    fn validate_notify_response_rejects_another_question() {
        let response = notify_response(1234, 0xa000, "other.com");

        let err = validate_notify_response(1234, &zone(), &response).unwrap_err();

        assert!(err.to_string().contains("another question"), "{err}");
    }
}
