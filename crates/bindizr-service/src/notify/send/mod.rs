//! Prepare NOTIFY targets and collect per-address send results.

use std::net::SocketAddr;
use std::time::Duration;

use bindizr_core::dns::name::{WireName, ZoneName};
use bindizr_core::dns::tsig::TsigSigningKey;
use bindizr_core::metrics::NotifyResult;
use bindizr_core::model::secondary::Secondary;
use thiserror::Error;
use tokio::sync::SemaphorePermit;
use tokio::task::JoinSet;

use crate::dns_client::SharedResolveAddressError;
use crate::dns_client::notify::NotifyHandle;
use crate::error::ServiceError;
use crate::secondary::SecondaryTarget;
use crate::types::CheckNotifyResponse;
use crate::{Context, dns_client, secondary, zone};

/// Why a NOTIFY target could not be reached or acknowledged.
#[derive(Debug, Error)]
pub(crate) enum NotifyTargetError {
    #[error(transparent)]
    Resolve(SharedResolveAddressError),
    #[error("{0}")]
    Send(#[source] dns_client::notify::SendNotifyError),
}

type NotifyOutcome = (String, Result<(), NotifyTargetError>);

/// Sending a zone's NOTIFY requests failed.
#[derive(Debug, Error)]
pub(crate) enum NotifyZoneError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// Failed targets and their original causes; whoever reports it names
    /// the zone.
    #[error("NOTIFY failed: {}", failures.iter().map(|(address, error)| format!("{address}: {error}")).collect::<Vec<_>>().join("; "))]
    TargetsFailed {
        failures: Vec<(String, NotifyTargetError)>,
    },
}

impl NotifyZoneError {
    /// Return whether the failure is Bindizr's own rather than a secondary's,
    /// which decides the level a failure that ends unreturned is logged at.
    pub(crate) fn is_server_fault(&self) -> bool {
        matches!(self, Self::Service(error) if error.code().is_internal())
    }
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

    let failures: Vec<_> = results
        .into_iter()
        .filter_map(|(address, result)| result.err().map(|error| (address, error)))
        .collect();

    if failures.is_empty() {
        Ok(())
    } else {
        Err(NotifyZoneError::TargetsFailed { failures })
    }
}

/// Notify the addresses already resolved by one diagnostic request.
pub(crate) async fn send_notify_to_targets<'a>(
    cx: &Context,
    zone_name: &ZoneName,
    targets: impl IntoIterator<Item = &'a SecondaryTarget>,
) -> Result<Vec<CheckNotifyResponse>, ServiceError> {
    let mut requests = NotifyRequests::begin(cx, zone_name).await?;
    let mut prepared = Vec::new();
    // A later key failure must precede every send, just as in the normal path.
    for target in targets {
        let key = find_signing_key(cx, &target.secondary).await?;
        prepared.push((target, key));
    }

    for (target, key) in prepared {
        requests.send(cx, target, key.as_ref()).await;
    }

    Ok(requests
        .complete(cx)
        .await
        .into_iter()
        .map(|(address, result)| CheckNotifyResponse {
            address,
            error: result.err().map(|error| error.to_string()),
        })
        .collect())
}

/// Send NOTIFY to selected secondaries and collect per-address outcomes.
async fn send_notify(
    cx: &Context,
    zone_name: &ZoneName,
    secondaries: Vec<Secondary>,
) -> Result<Vec<NotifyOutcome>, ServiceError> {
    let mut requests = NotifyRequests::begin(cx, zone_name).await?;
    let timeout = requests.timeout;
    let mut preparations = JoinSet::new();

    for secondary in secondaries {
        let key = find_signing_key(cx, &secondary).await?;
        preparations
            .spawn(async move { (SecondaryTarget::resolve(secondary, timeout).await, key) });
    }

    while let Some(result) = preparations.join_next().await {
        let (target, key) = result.map_err(|error| {
            ServiceError::internal_with_source("NOTIFY address resolution task failed", error)
        })?;
        requests.send(cx, &target, key.as_ref()).await;
    }

    Ok(requests.complete(cx).await)
}

/// An unusable stored key fails the whole round before any target receives a request.
async fn find_signing_key(
    cx: &Context,
    secondary: &Secondary,
) -> Result<Option<TsigSigningKey>, ServiceError> {
    secondary::find_notify_signing_key(cx, secondary)
        .await
        .inspect_err(|_| cx.metrics().track_notify(NotifyResult::Failed))
}

/// Prepared sends and results for one zone, holding a preparation slot until all sends are queued.
#[derive(Debug)]
struct NotifyRequests<'a> {
    permit: SemaphorePermit<'a>,
    qname: WireName,
    timeout: Duration,
    retries: u32,
    handles: Vec<(SocketAddr, NotifyHandle)>,
    results: Vec<NotifyOutcome>,
}

impl<'a> NotifyRequests<'a> {
    /// Reserve a preparation slot and encode the NOTIFY question.
    async fn begin(cx: &'a Context, zone_name: &ZoneName) -> Result<Self, ServiceError> {
        let qname = zone_name
            .to_wire_name()
            .map_err(|error| ServiceError::internal_with_source("invalid zone name", error))?;
        let config = cx.config();
        let permit = cx.notify_preparations().acquire().await.map_err(|error| {
            ServiceError::internal_with_source("NOTIFY preparation queue closed", error)
        })?;

        Ok(Self {
            permit,
            qname,
            timeout: config.dns.notify.timeout(),
            retries: config.dns.notify.retries,
            handles: Vec::new(),
            results: Vec::new(),
        })
    }

    /// Queue a NOTIFY for every resolved address or record the preparation failure.
    async fn send(&mut self, cx: &Context, target: &SecondaryTarget, key: Option<&TsigSigningKey>) {
        let addrs = match &target.addresses {
            Ok(addrs) => addrs,
            Err(error) => {
                cx.metrics().track_notify(NotifyResult::ResolveFailed);
                self.results.push((
                    target.secondary.address.to_string(),
                    Err(NotifyTargetError::Resolve(error.clone().into())),
                ));
                return;
            }
        };

        for &addr in addrs {
            match cx
                .notify_client()
                .send(&self.qname, addr, self.timeout, self.retries, key)
                .await
            {
                Ok(handle) => self.handles.push((addr, handle)),
                Err(error) => {
                    cx.metrics().track_notify(NotifyResult::Failed);
                    self.results
                        .push((addr.to_string(), Err(NotifyTargetError::Send(error))));
                }
            }
        }
    }

    /// Release the preparation slot before waiting for every enqueued request.
    async fn complete(mut self, cx: &Context) -> Vec<NotifyOutcome> {
        drop(self.permit);
        for (addr, handle) in self.handles {
            let result = match handle.wait().await {
                Ok(()) => {
                    log::info!("NOTIFY sent successfully to {addr}");
                    cx.metrics().track_notify(NotifyResult::Ok);
                    Ok(())
                }
                // Returned, not logged: the caller that ends the failure reports it.
                Err(error) => {
                    cx.metrics().track_notify(NotifyResult::Failed);
                    Err(NotifyTargetError::Send(error))
                }
            };
            self.results.push((addr.to_string(), result));
        }

        self.results
    }
}

#[cfg(test)]
mod tests;
