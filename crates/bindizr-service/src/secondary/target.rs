//! Selected secondary rows and their address resolution, shared within one diagnostic request.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bindizr_core::model::secondary::Secondary;
use tokio::task::JoinSet;

use crate::dns_client::ResolveAddressError;
use crate::error::ServiceError;
use crate::{Context, dns_client, secondary};

/// A diagnostic target, including a resolution failure that each report must describe alike.
#[derive(Debug, Clone)]
pub(crate) struct SecondaryTarget {
    pub(crate) secondary: Secondary,
    pub(crate) addresses: Result<Vec<SocketAddr>, Arc<ResolveAddressError>>,
}

impl SecondaryTarget {
    /// Resolve this selected row once for its probe, history, and NOTIFY stages.
    pub(crate) async fn resolve(secondary: Secondary, timeout: Duration) -> Self {
        let addresses = dns_client::resolve_address_entry(&secondary.address, timeout)
            .await
            .map_err(Arc::new);
        Self {
            secondary,
            addresses,
        }
    }

    /// Return the canonical client IPs the transfer log stores, none on resolution failure.
    pub(crate) fn client_ips(&self) -> Vec<IpAddr> {
        self.addresses.as_ref().map_or_else(
            |_| Vec::new(),
            |addrs| addrs.iter().map(|addr| addr.ip().to_canonical()).collect(),
        )
    }
}

/// Select enabled secondary rows once and resolve them concurrently in their listing order.
pub(crate) async fn resolve_enabled(cx: &Context) -> Result<Vec<SecondaryTarget>, ServiceError> {
    let secondaries = secondary::list_enabled(cx).await?;
    let timeout = cx.config().dns.notify.timeout();
    let mut tasks = JoinSet::new();
    for (index, secondary) in secondaries.into_iter().enumerate() {
        tasks.spawn(async move { (index, SecondaryTarget::resolve(secondary, timeout).await) });
    }
    let mut targets = Vec::new();
    while let Some(result) = tasks.join_next().await {
        targets.push(result.map_err(|error| {
            ServiceError::internal_with_source("secondary address resolution task failed", error)
        })?);
    }
    targets.sort_unstable_by_key(|(index, _)| *index);
    Ok(targets.into_iter().map(|(_, target)| target).collect())
}
