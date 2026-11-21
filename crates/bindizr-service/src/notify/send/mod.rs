//! Prepare NOTIFY targets and collect per-address send results.

use bindizr_core::dns::name::ZoneName;
use bindizr_core::metrics::NotifyResult;
use bindizr_core::model::secondary::Secondary;
use thiserror::Error;
use tokio::task::JoinSet;

use crate::dns_client::ResolveAddressError;
use crate::error::ServiceError;
use crate::types::CheckNotifyResponse;
use crate::{Context, dns_client, secondary, zone};

/// Why a NOTIFY target could not be reached or acknowledged.
#[derive(Debug, Error)]
pub(crate) enum SendNotifyError {
    #[error("failed to resolve: {0}")]
    Resolve(#[source] ResolveAddressError),
    #[error("{0}")]
    Send(#[source] dns_client::notify::SendNotifyError),
}

/// Sending a zone's NOTIFY requests failed.
#[derive(Debug, Error)]
pub(crate) enum NotifyZoneError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// Failed targets and their original causes; whoever reports it names
    /// the zone.
    #[error("NOTIFY failed: {}", failures.iter().map(|(address, error)| format!("{address}: {error}")).collect::<Vec<_>>().join("; "))]
    TargetsFailed {
        failures: Vec<(String, SendNotifyError)>,
    },
}

/// Notify every enabled secondary for one zone the DNS plane serves; a zone
/// it does not serve, disabled or gone, is skipped, since its SOA answers NOTAUTH.
pub(crate) async fn send_zone_notify(
    cx: &Context,
    zone_name: &ZoneName,
) -> Result<(), NotifyZoneError> {
    // The catalog is virtual: served whenever the DNS plane is.
    if zone_name != &cx.config().dns.catalog_zone_name
        && zone::find_served_by_name(cx, zone_name).await?.is_none()
    {
        log::info!("Skipping NOTIFY for zone {zone_name}: not served");
        return Ok(());
    }

    log::info!("Sending NOTIFY for zone: {zone_name}");

    let secondaries = secondary::list_enabled(cx).await?;
    let results = send_notify(cx, zone_name, secondaries).await?;

    if results.is_empty() {
        log::info!("No enabled secondaries");
        return Ok(());
    }

    let failures: Vec<(String, SendNotifyError)> = results
        .into_iter()
        .filter_map(|(address, result)| result.err().map(|error| (address, error)))
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(NotifyZoneError::TargetsFailed { failures })
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

/// Format send results for a diagnostic response.
fn build_notify_reports(
    results: Vec<(String, Result<(), SendNotifyError>)>,
) -> Vec<CheckNotifyResponse> {
    results
        .into_iter()
        .map(|(address, result)| CheckNotifyResponse {
            address,
            error: result.err().map(|error| error.to_string()),
        })
        .collect()
}

/// Send NOTIFY to selected secondaries and collect per-address outcomes.
async fn send_notify(
    cx: &Context,
    zone_name: &ZoneName,
    secondaries: Vec<Secondary>,
) -> Result<Vec<(String, Result<(), SendNotifyError>)>, ServiceError> {
    // An invalid stored zone name is a server fault.
    let qname = zone_name
        .to_wire_name()
        .map_err(|error| ServiceError::internal_with_source("invalid zone name", error))?;
    let timeout = cx.config().dns.notify.timeout();
    let retries = cx.config().dns.notify.retries;

    let permit = cx.notify_preparations().acquire().await.map_err(|error| {
        ServiceError::internal_with_source("NOTIFY preparation queue closed", error)
    })?;

    let mut preparations = JoinSet::new();
    let mut results = Vec::new();

    for secondary in secondaries {
        // A stored key that will not load is a server fault, not a target's
        // outcome: returned whole, so where it ends logs it.
        let key = match secondary::find_notify_signing_key(cx, &secondary).await {
            Ok(key) => key,
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                return Err(error);
            }
        };
        preparations.spawn(async move {
            let addrs = dns_client::resolve_address_entry(&secondary.address, timeout).await;
            (secondary.address, key, addrs)
        });
    }

    let mut handles = Vec::new();

    while let Some(result) = preparations.join_next().await {
        let (address, key, addrs) = result.map_err(|error| {
            ServiceError::internal_with_source("NOTIFY address resolution task failed", error)
        })?;
        let addrs = match addrs {
            Ok(addrs) => addrs,
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::ResolveFailed);
                results.push((address.to_string(), Err(SendNotifyError::Resolve(error))));
                continue;
            }
        };

        for addr in addrs {
            match cx
                .notify_client()
                .send(&qname, addr, timeout, retries, key.as_ref())
                .await
            {
                Ok(handle) => handles.push((addr, handle)),
                Err(error) => {
                    cx.metrics().track_notify(NotifyResult::Failed);
                    results.push((addr.to_string(), Err(SendNotifyError::Send(error))));
                }
            }
        }
    }

    // Release preparation slots before waiting for ACKs.
    drop(permit);

    for (addr, handle) in handles {
        let result = match handle.wait().await {
            Ok(()) => {
                log::info!("NOTIFY sent successfully to {addr}");
                cx.metrics().track_notify(NotifyResult::Ok);
                Ok(())
            }
            // Returned, not logged: the caller that ends the failure reports it.
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::Failed);
                Err(SendNotifyError::Send(error))
            }
        };
        results.push((addr.to_string(), result));
    }

    Ok(results)
}

#[cfg(test)]
mod tests;
