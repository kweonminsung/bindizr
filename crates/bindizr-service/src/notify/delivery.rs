//! Prepare NOTIFY targets and collect per-address delivery outcomes.
use bindizr_core::{dns::name::ZoneName, metrics::NotifyResult};
use thiserror::Error;
use tokio::task::JoinSet;

use crate::{
    Context,
    dns_client::{ResolveAddressError, notify::SendNotifyError},
    error::ServiceError,
    model::secondary::Secondary,
    secondary,
    types::CheckNotifyResponse,
};

/// Why a NOTIFY target could not be reached or acknowledged.
#[derive(Debug, Error)]
pub enum NotifyDeliveryError {
    #[error("{0}")]
    Key(#[source] ServiceError),
    #[error("failed to resolve: {0}")]
    Resolve(#[source] ResolveAddressError),
    #[error("{0}")]
    Send(#[source] SendNotifyError),
}

/// A zone's NOTIFY delivery failed.
#[derive(Debug, Error)]
pub enum NotifyZoneError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// Failed targets and their original causes.
    #[error("NOTIFY failed for zone {zone_name} ({})", failures.iter().map(|(address, error)| format!("{address}: {error}")).collect::<Vec<_>>().join("; "))]
    Undelivered {
        zone_name: String,
        failures: Vec<(String, NotifyDeliveryError)>,
    },
}

/// Notify every enabled secondary for one zone.
pub(crate) async fn send_zone_notify(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<(), NotifyZoneError> {
    log::info!("Sending NOTIFY for zone: {}", zone_name);

    let secondaries = secondary::list_enabled(cx).await?;
    let results = send_notify(cx, zone_name, secondaries).await?;
    if results.is_empty() {
        log::info!("No enabled secondaries");
        return Ok(());
    }

    let failures: Vec<(String, NotifyDeliveryError)> = results
        .into_iter()
        .filter_map(|(address, result)| result.err().map(|error| (address, error)))
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
    Ok(build_notify_reports(
        send_notify(cx, zone_name, secondaries).await?,
    ))
}

/// Notify one secondary's addresses using its configured signing key.
pub async fn send_notify_to_secondary(
    cx: &Context,
    zone_name: &ZoneName,
    secondary: &Secondary,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    Ok(build_notify_reports(
        send_notify(cx, zone_name, vec![secondary.clone()]).await?,
    ))
}

/// Format delivery outcomes for a diagnostic response.
fn build_notify_reports(
    results: Vec<(String, Result<(), NotifyDeliveryError>)>,
) -> Vec<CheckNotifyResponse> {
    results
        .into_iter()
        .map(|(address, result)| CheckNotifyResponse {
            address,
            error: result.err().map(|error| error.to_string()),
        })
        .collect()
}

/// Deliver NOTIFY to selected secondaries and collect per-address outcomes.
async fn send_notify(
    cx: &Context,
    zone_name: &ZoneName,
    secondaries: Vec<Secondary>,
) -> Result<Vec<(String, Result<(), NotifyDeliveryError>)>, ServiceError> {
    // An invalid stored zone name is a server fault.
    let qname = zone_name
        .to_wire_name()
        .map_err(|e| ServiceError::internal_with_source(format!("invalid zone name: {}", e), e))?;
    let timeout = cx.config().dns.notify.timeout();
    let retries = cx.config().dns.notify.retries;

    let permit = cx.notify_preparations().acquire().await.map_err(|error| {
        ServiceError::internal_with_source("NOTIFY preparation queue closed", error)
    })?;
    let mut preparations = JoinSet::new();
    let mut results = Vec::new();
    for secondary in secondaries {
        let key = match secondary::find_notify_signing_key(cx, &secondary).await {
            Ok(key) => key,
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                results.push((
                    secondary.address.to_string(),
                    Err(NotifyDeliveryError::Key(error)),
                ));
                continue;
            }
        };
        preparations.spawn(async move {
            let addresses =
                crate::dns_client::resolve_address_entry(&secondary.address, timeout).await;
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
                results.push((
                    address.to_string(),
                    Err(NotifyDeliveryError::Resolve(error)),
                ));
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
                    results.push((address.to_string(), Err(NotifyDeliveryError::Send(error))));
                }
            }
        }
    }
    // Release preparation slots before waiting for ACKs.
    drop(permit);
    for (address, delivery) in deliveries {
        let result = match delivery.wait().await {
            Ok(()) => {
                log::info!("NOTIFY sent successfully to {}", address);
                cx.metrics().track_notify(NotifyResult::Ok);
                Ok(())
            }
            Err(error) => {
                log::error!("Failed to send NOTIFY to {}: {}", address, error);
                cx.metrics().track_notify(NotifyResult::Failed);
                Err(NotifyDeliveryError::Send(error))
            }
        };
        results.push((address.to_string(), result));
    }
    Ok(results)
}

#[cfg(test)]
mod tests;
