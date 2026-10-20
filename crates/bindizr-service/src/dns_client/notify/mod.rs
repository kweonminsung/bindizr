mod client;

use bindizr_core::{dns::name::ZoneName, metrics::NotifyResult};
pub(crate) use client::NotifyClient;
use thiserror::Error;
use tokio::task::JoinSet;

use super::ExchangeMessageError;
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
    #[error("NOTIFY socket dispatcher closed")]
    DispatcherClosed,
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

    let permit = cx
        .notify_client()
        .preparations
        .acquire()
        .await
        .map_err(|error| {
            ServiceError::internal_with_source("NOTIFY preparation queue closed", error)
        })?;
    let mut preparations = JoinSet::new();
    let mut reports = Vec::new();
    for secondary in secondaries {
        let key = match secondary::find_notify_signing_key(cx, &secondary).await {
            Ok(key) => key,
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                reports.push(CheckNotifyResponse {
                    address: secondary.address.to_string(),
                    error: Some(error.to_string()),
                });
                continue;
            }
        };
        preparations.spawn(async move {
            let addresses = super::resolve_address_entry(&secondary.address, timeout).await;
            (secondary.address, key, addresses)
        });
    }
    let mut deliveries = Vec::new();
    while let Some(result) = preparations.join_next().await {
        let (address, key, addresses) = result.map_err(|error| {
            ServiceError::internal_with_source("NOTIFY address resolution task failed", error)
        })?;
        let addresses = match addresses {
            Ok(addresses) => addresses,
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::ResolveFailed);
                reports.push(CheckNotifyResponse {
                    address: address.to_string(),
                    error: Some(format!("failed to resolve: {error}")),
                });
                continue;
            }
        };
        for address in addresses {
            match cx
                .notify_client()
                .start(&qname, address, timeout, retries, key.as_ref())
                .await
            {
                Ok(delivery) => deliveries.push((address, delivery)),
                Err(error) => {
                    cx.metrics().track_notify(NotifyResult::Failed);
                    reports.push(CheckNotifyResponse {
                        address: address.to_string(),
                        error: Some(error.to_string()),
                    });
                }
            }
        }
    }
    // All datagrams are scheduled before waiting; ACKs never hold preparation slots.
    drop(permit);
    for (address, delivery) in deliveries {
        let error = match delivery.wait().await {
            Ok(()) => {
                log::info!("NOTIFY sent successfully to {}", address);
                cx.metrics().track_notify(NotifyResult::Ok);
                None
            }
            Err(error) => {
                log::error!("Failed to send NOTIFY to {}: {}", address, error);
                cx.metrics().track_notify(NotifyResult::Failed);
                Some(error.to_string())
            }
        };
        reports.push(CheckNotifyResponse {
            address: address.to_string(),
            error,
        });
    }
    Ok(reports)
}

#[cfg(test)]
mod tests;
