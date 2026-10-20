use std::{net::SocketAddr, time::Duration};

use bindizr_core::{
    dns::{
        message::{Name, OptRcode},
        name::ZoneName,
        query::{ParseResponseError, build_notify_query, validate_notify_response},
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

/// Notify every enabled secondary for one zone.
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

/// Notify enabled secondaries and report each resolved address.
pub async fn send_notify_to_secondaries(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    let secondaries = secondary::list_enabled(cx).await?;
    send_notify(cx, zone_name, secondaries).await
}

/// Notify one secondary's addresses using its configured signing key.
pub async fn send_notify_to_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    send_notify(cx, zone_name, vec![secondary.clone()]).await
}

/// Resolve and notify the given secondaries, reporting each address.
async fn send_notify(
    cx: &Context,
    zone_name: &ZoneName,
    secondaries: Vec<Secondary>,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    // An invalid stored zone name is a server fault.
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

/// Send one NOTIFY, retransmitting it `retries` times on silence (RFC 1996,
/// Section 3.6) and authenticating the response before reading its RCODE.
async fn send_notify_to_server(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
    retries: u32,
    tsig_key: Option<&TsigSigningKey>,
) -> Result<(), SendNotifyError> {
    let (query_id, mut builder) = build_notify_query(qname, tsig_key);
    let verifier = match tsig_key {
        Some(tsig_key) => Some(sign_request(&mut builder, tsig_key.clone())?),
        None => None,
    };
    let notify_message = builder.finish();

    let (received, response) = super::exchange_over_udp_checked(
        server_addr,
        timeout,
        &notify_message,
        "NOTIFY",
        retries.saturating_add(1),
        |response| match verifier.as_ref() {
            None => true,
            Some(verifier) => match verify_response(verifier, response) {
                Ok(()) => true,
                Err(error) if error.is_authenticated() => true,
                // RFC 8945, Section 5.4: an unsigned or unverifiable answer is
                // logged and ignored while the request waits for a signed one.
                Err(error) => {
                    log::warn!(
                        "Ignoring an unauthenticated NOTIFY response from {}: {}",
                        server_addr,
                        error
                    );
                    false
                }
            },
        },
    )
    .await?;

    log::info!(
        "NOTIFY message sent to {} ({} bytes, signed={})",
        server_addr,
        notify_message.len(),
        verifier.is_some()
    );

    if let Some(verifier) = &verifier {
        verify_response(verifier, &response[..received])?;
    }
    match validate_notify_response(query_id, qname, &response[..received]) {
        // RFC 1996, Section 3.12: a validated NOTIMP completes the transaction.
        Err(ParseResponseError::NotifyRcode(OptRcode::NOTIMP)) => {
            log::warn!(
                "Server {} does not support NOTIFY; transaction complete",
                server_addr
            );
        }
        result => result?,
    }

    Ok(())
}

#[cfg(test)]
mod tests;
