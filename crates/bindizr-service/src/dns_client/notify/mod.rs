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

use super::ExchangeError;
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

    let mut reports = Vec::new();
    for secondary in &secondaries {
        reports.extend(send_notify_to_secondary(cx, zone_name, secondary).await?);
    }
    Ok(reports)
}

/// Send NOTIFY for a zone to every resolved address of one secondary, signed
/// with its NOTIFY key when it has one; one outcome per address.
pub async fn send_notify_to_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
) -> Result<Vec<NotifyCheckResponse>, ServiceError> {
    let dns_config = &cx.config().dns;
    let timeout = Duration::from_secs(dns_config.notify.timeout_secs);
    let retries = dns_config.notify.retries;
    // The zone name is a stored row, so one that does not parse is the
    // server's fault.
    let qname = zone_name
        .to_wire_name()
        .map_err(|e| ServiceError::internal(format!("invalid zone name: {}", e)))?;

    let key = match secondary::notify_signing_key(cx, secondary).await {
        Ok(key) => key,
        Err(e) => {
            cx.metrics().track_notify(NotifyResult::Failed);
            return Ok(vec![NotifyCheckResponse {
                address: secondary.address.clone(),
                error: Some(e.to_string()),
            }]);
        }
    };
    let addrs = match super::resolve_address_entry(&secondary.address, timeout).await {
        Ok(addrs) => addrs,
        Err(e) => {
            cx.metrics().track_notify(NotifyResult::ResolveFailed);
            return Ok(vec![NotifyCheckResponse {
                address: secondary.address.clone(),
                error: Some(format!("failed to resolve: {}", e)),
            }]);
        }
    };

    let mut reports = Vec::new();
    for addr in addrs {
        let result = match send_notify_to_server(&qname, addr, timeout, retries, key.as_ref()).await
        {
            Ok(()) => {
                log::info!("NOTIFY sent successfully to {}", addr);
                cx.metrics().track_notify(NotifyResult::Ok);
                Ok(())
            }
            Err(e) => {
                log::error!("Failed to send NOTIFY to {}: {}", addr, e);
                cx.metrics().track_notify(NotifyResult::Failed);
                Err(e)
            }
        };
        reports.push(NotifyCheckResponse {
            address: addr.to_string(),
            error: result.err().map(|e| e.to_string()),
        });
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
    let mut last_error = None;

    for attempt in 1..=attempts {
        match send_notify_to_server_once(qname, server_addr, timeout, key).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt < attempts {
                    log::info!(
                        "Retrying NOTIFY to {} ({}/{}) after error: {}",
                        server_addr,
                        attempt + 1,
                        attempts,
                        e
                    );
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.expect("attempts is at least one"))
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
mod tests;
