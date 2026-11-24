//! Propagate committed changes by NOTIFY, inline or batched by `queue` per `dns.notify.batch_ms`.

pub mod queue;
mod send;

use std::sync::Arc;

use bindizr_core::dns::name::ZoneName;
pub(crate) use send::{NotifyZoneError, send_notify_to_targets, send_zone_notify};
use thiserror::Error;
use tokio::task::JoinSet;

use crate::error::ServiceError;
use crate::{Context, zone};

/// Bound key/address preparation without occupying slots while waiting for ACKs.
pub(crate) const CONCURRENT_PREPARATIONS: usize = 16;

/// Which zones a NOTIFY round covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyTarget<'a> {
    All,
    Zone(&'a ZoneName),
}

/// Why a NOTIFY round did not reach every secondary.
#[derive(Debug, Error)]
pub(crate) enum NotifyError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Zone(#[from] NotifyZoneError),
    /// All zones whose NOTIFY failed, when all were sent.
    #[error("NOTIFY failed for {}", failures.iter().map(|(zone_name, error)| format!("{zone_name}: {error}")).collect::<Vec<_>>().join("; "))]
    Zones {
        failures: Vec<(String, NotifyZoneError)>,
    },
}

impl From<NotifyError> for ServiceError {
    /// Report a post-commit NOTIFY failure as an internal error, keeping it as
    /// source; the requester cannot repair secondaries.
    fn from(error: NotifyError) -> Self {
        match error {
            NotifyError::Service(error) => error,
            other => Self::internal_with_source(other.to_string(), other),
        }
    }
}

/// Notify one or all zones and aggregate failures; this layer enumerates the zones.
pub(crate) async fn send_notify(
    cx: &Arc<Context>,
    target: NotifyTarget<'_>,
) -> Result<(), NotifyError> {
    match target {
        NotifyTarget::All => {
            let zones = zone::list_enabled(cx).await?;
            send_zone_notifies(cx, zones.into_iter().map(|zone| zone.name)).await
        }
        NotifyTarget::Zone(zone_name) => Ok(send::send_zone_notify(cx, zone_name).await?),
    }
}

/// Announce the selected zones concurrently and return their failures together.
pub(crate) async fn send_zone_notifies(
    cx: &Arc<Context>,
    zone_names: impl IntoIterator<Item = ZoneName>,
) -> Result<(), NotifyError> {
    let mut failures = Vec::new();
    let mut tasks = JoinSet::new();

    for zone_name in zone_names {
        let cx = cx.clone();
        tasks.spawn(async move {
            let result = send::send_zone_notify(&cx, &zone_name).await;
            (zone_name.to_string(), result)
        });
    }

    while let Some(result) = tasks.join_next().await {
        let (zone_name, result) = result
            .map_err(|error| ServiceError::internal_with_source("NOTIFY task failed", error))?;
        // Returned whole to the boundary, which logs it once.
        if let Err(error) = result {
            failures.push((zone_name, error));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(NotifyError::Zones { failures })
    }
}

/// Send NOTIFY after commit, queued when batching is enabled and inline otherwise.
/// Log failures without failing the committed write.
pub(crate) async fn notify_after_update(cx: &Context, zone_name: &ZoneName) {
    if cx.config().dns.notify.batch_ms > 0 && cx.enqueue_notify(zone_name) {
        return;
    }

    if let Err(error) = send::send_zone_notify(cx, zone_name).await {
        if error.is_server_fault() {
            log::error!("Failed to send NOTIFY for zone {zone_name}: {error:?}");
        } else {
            log::warn!("Failed to send NOTIFY for zone {zone_name}: {error:?}");
        }
    }
}
