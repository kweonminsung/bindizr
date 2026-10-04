//! When a committed change is propagated: the NOTIFY entry points and the
//! `dns.notify.batch_ms` choice between sending inline and queueing. The
//! batching worker lives in `queue`.

pub mod queue;

use bindizr_core::dns::name::ZoneName;
use thiserror::Error;

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

/// Send a DNS NOTIFY for one zone, or for all zones, aggregating per-zone
/// failures. Enumerating the zones is this layer's call, not the client's.
pub(crate) async fn send_notify(cx: &Context, target: NotifyTarget<'_>) -> Result<(), NotifyError> {
    let NotifyTarget::Zone(zone_name) = target else {
        let zones = crate::zone::list(cx).await?;
        let mut failures = Vec::new();
        for zone in zones {
            if let Err(e) = crate::dns_client::notify::send_zone_notify(cx, &zone.name).await {
                log::warn!("Failed to send NOTIFY for zone {}: {}", zone.name, e);
                failures.push((zone.name.to_string(), e));
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

/// NOTIFY the secondaries after a zone update: queued when `dns.notify.batch_ms`
/// sets a window, otherwise sent inline before the write is answered. The write
/// has committed, so a failure is logged rather than reported.
pub(crate) async fn notify_after_update(cx: &Context, zone_name: &ZoneName) {
    if cx.config().dns.notify.batch_ms > 0 && cx.enqueue_notify(NotifyTarget::Zone(zone_name)) {
        return;
    }

    if let Err(e) = send_notify(cx, NotifyTarget::Zone(zone_name)).await {
        log::warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
    }
}
