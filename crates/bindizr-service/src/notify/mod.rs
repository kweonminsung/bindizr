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

/// Report post-commit NOTIFY failures as server errors; the requester cannot repair secondaries.
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

/// Notify one or all zones and aggregate failures; this layer enumerates the zones.
pub(crate) async fn send_notify(
    cx: &Arc<Context>,
    target: NotifyTarget<'_>,
) -> Result<(), NotifyError> {
    let NotifyTarget::Zone(zone_name) = target else {
        let zones = crate::zone::list(cx).await?;
        let mut failures = Vec::new();
        let mut tasks = JoinSet::new();
        for zone in zones {
            let cx = cx.clone();
            tasks.spawn(async move {
                let result = crate::dns_client::notify::send_zone_notify(&cx, &zone.name).await;
                (zone.name.to_string(), result)
            });
        }
        while let Some(result) = tasks.join_next().await {
            let (zone_name, result) = result
                .map_err(|error| ServiceError::internal_with_source("NOTIFY task failed", error))?;
            if let Err(error) = result {
                log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, error);
                failures.push((zone_name, error));
            }
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
