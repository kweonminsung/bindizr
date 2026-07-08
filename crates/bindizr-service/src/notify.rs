use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use bindizr_core::config::{self, ApplyMode};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};

use crate::log_warn;

#[async_trait]
pub trait NotifySender: Send + Sync {
    async fn send_notify(&self, zone_name: Option<&str>) -> Result<(), String>;
}

static NOTIFY_SENDER: OnceLock<Arc<dyn NotifySender>> = OnceLock::new();

/// Register the global NOTIFY sender; fails if one is already registered.
pub fn set_notify_sender(sender: Arc<dyn NotifySender>) -> Result<(), &'static str> {
    NOTIFY_SENDER
        .set(sender)
        .map_err(|_| "notify sender is already registered")
}

/// Send a DNS NOTIFY for `zone_name` (or all zones) via the registered sender.
pub async fn send_notify(zone_name: Option<&str>) -> Result<(), String> {
    match NOTIFY_SENDER.get() {
        Some(sender) => sender.send_notify(zone_name).await,
        None => Err("notify sender is not registered".to_string()),
    }
}

// --- Async apply queue --------------------------------------------------------

/// A queued propagation job: send NOTIFY for one zone, or for all zones (`None`).
#[derive(Debug)]
struct ApplyJob {
    zone_name: Option<String>,
}

static APPLY_QUEUE: OnceLock<UnboundedSender<ApplyJob>> = OnceLock::new();

/// Spawn the background apply worker that drains queued NOTIFY jobs. Only the
/// first call installs the queue; later calls are no-ops. Must be called from a
/// Tokio runtime (e.g. during service bootstrap) for `apply_mode = async` to
/// take effect; without it, writes fall back to inline NOTIFY.
pub fn init_apply_worker() {
    let (tx, mut rx) = unbounded_channel::<ApplyJob>();
    if APPLY_QUEUE.set(tx).is_err() {
        return; // already initialized
    }

    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            if let Err(e) = send_notify(job.zone_name.as_deref()).await {
                log_warn!(
                    "async apply: NOTIFY failed for zone {}: {}",
                    job.zone_name.as_deref().unwrap_or("<all>"),
                    e
                );
            }
        }
    });
}

/// Queue a NOTIFY for later delivery. Returns `false` if the worker was never
/// started, so the caller can fall back to sending inline.
fn enqueue_apply(zone_name: Option<&str>) -> bool {
    match APPLY_QUEUE.get() {
        Some(tx) => tx
            .send(ApplyJob {
                zone_name: zone_name.map(str::to_string),
            })
            .is_ok(),
        None => false,
    }
}

/// Send a NOTIFY after a zone update, unless disabled by `notify_after_update`.
///
/// In `apply_mode = async` the NOTIFY is handed to the background worker and this
/// returns immediately (the write no longer waits on propagation). In `sync` mode
/// — or if the worker is not running — it sends inline as before.
pub async fn send_notify_after_update(zone_name: Option<&str>) -> Result<(), String> {
    let dns = &config::get_bindizr_config().dns;
    if !dns.notify_after_update {
        return Ok(());
    }

    if dns.apply_mode == ApplyMode::Async && enqueue_apply(zone_name) {
        return Ok(());
    }

    send_notify(zone_name).await
}
