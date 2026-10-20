//! Propagate committed changes by NOTIFY, inline or batched by `queue` per `dns.notify.batch_ms`.

pub mod queue;

use std::sync::Arc;

use bindizr_core::dns::name::ZoneName;
use thiserror::Error;
use tokio::task::JoinSet;

use crate::{Context, dns_client::notify::NotifyZoneError, error::ServiceError};

/// Which zones a NOTIFY round covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyTarget<'a> {
    All,
    Zone(&'a ZoneName),
}

/// Why a NOTIFY round did not reach every secondary.
#[derive(Debug, Error)]
pub enum NotifyError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Zone(#[from] NotifyZoneError),
    /// All zones whose NOTIFY failed, when all were sent.
    #[error("NOTIFY failed for {}", failures.iter().map(|(zone, error)| format!("{zone}: {error}")).collect::<Vec<_>>().join("; "))]
    Zones {
        failures: Vec<(String, NotifyZoneError)>,
    },
}

/// A NOTIFY that did not go out is the server's to report: the change has
/// committed, and the requester can do nothing about the secondaries.
impl From<NotifyError> for ServiceError {
    /// Report the NOTIFY failure as an internal error, keeping it as source.
    fn from(err: NotifyError) -> Self {
        match err {
            NotifyError::Service(err) => err,
            other => ServiceError::Internal {
                message: other.to_string(),
                source: Some(Box::new(other)),
            },
        }
    }
}

/// Zones an all-zones round notifies at once: concurrency keeps one silent
/// secondary from delaying later zones (RFC 1996, Section 4.3), bounded for sockets.
const CONCURRENT_ZONE_NOTIFIES: usize = 16;

/// Send a DNS NOTIFY for one zone, or for all zones, aggregating per-zone
/// failures. Enumerating the zones is this layer's call, not the client's.
pub(crate) async fn send_notify(
    cx: &Arc<Context>,
    target: NotifyTarget<'_>,
) -> Result<(), NotifyError> {
    let NotifyTarget::Zone(zone_name) = target else {
        let zones = crate::zone::list(cx).await?;
        let mut failures = Vec::new();
        let mut tasks = JoinSet::new();
        let mut collect = |result: Result<_, tokio::task::JoinError>| match result {
            Ok((zone_name, Err(e))) => {
                log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
                failures.push((zone_name, e));
            }
            Ok((_, Ok(()))) => {}
            Err(e) => log::warn!("NOTIFY task failed: {}", e),
        };
        for zone in zones {
            if tasks.len() >= CONCURRENT_ZONE_NOTIFIES
                && let Some(result) = tasks.join_next().await
            {
                collect(result);
            }
            let cx = cx.clone();
            tasks.spawn(async move {
                let result = crate::dns_client::notify::send_zone_notify(&cx, &zone.name).await;
                (zone.name.to_string(), result)
            });
        }
        while let Some(result) = tasks.join_next().await {
            collect(result);
        }
        return if failures.is_empty() {
            Ok(())
        } else {
            Err(NotifyError::Zones { failures })
        };
    };
    Ok(crate::dns_client::notify::send_zone_notify(cx, zone_name).await?)
}

/// NOTIFY after commit, queued when batching is enabled and inline otherwise.
/// Log failures without failing the committed write.
pub(crate) async fn notify_after_update(cx: &Context, zone_name: &ZoneName) {
    if cx.config().dns.notify.batch_ms > 0 && cx.enqueue_notify(NotifyTarget::Zone(zone_name)) {
        return;
    }

    if let Err(e) = crate::dns_client::notify::send_zone_notify(cx, zone_name).await {
        log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
    }
}
