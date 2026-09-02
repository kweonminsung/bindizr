//! The async apply queue: committed writes enqueue a NOTIFY here and return,
//! and the worker batches a burst into one NOTIFY per zone.

use std::{collections::HashSet, sync::OnceLock, time::Duration};

use bindizr_core::config;
use tokio::{
    sync::mpsc::{UnboundedSender, unbounded_channel},
    time::{Instant, timeout},
};

use super::send_notify;
use crate::log_warn;

/// A queued propagation job: send NOTIFY for one zone, or for all zones (`None`).
#[derive(Debug)]
struct ApplyJob {
    zone_name: Option<String>,
}

static APPLY_QUEUE: OnceLock<UnboundedSender<ApplyJob>> = OnceLock::new();

/// Spawn the background worker that drains queued NOTIFYs. First call wins;
/// later calls are no-ops. Without it, async-mode writes fall back to inline.
pub fn init_notify_worker() {
    let (tx, mut rx) = unbounded_channel::<ApplyJob>();
    if APPLY_QUEUE.set(tx).is_err() {
        return; // already initialized
    }

    tokio::spawn(async move {
        // Block for the first job, then batch everything that arrives within
        // the configured window into a single NOTIFY per zone.
        while let Some(first) = rx.recv().await {
            let mut batch = NotifyBatch::default();
            batch.add(first);

            let window = Duration::from_millis(config::bindizr_config().dns.notify_batch_ms);
            if !window.is_zero() {
                let deadline = Instant::now() + window;
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match timeout(remaining, rx.recv()).await {
                        Ok(Some(job)) => batch.add(job),
                        Ok(None) => break, // channel closed; flush what we have
                        Err(_) => break,   // window elapsed
                    }
                }
            }
            // Drain anything already queued (covers a zero-length window too).
            while let Ok(job) = rx.try_recv() {
                batch.add(job);
            }

            batch.flush().await;
        }
    });
}

/// Accumulates queued jobs so a burst collapses to one NOTIFY per zone. An
/// all-zones job supersedes every per-zone job in the same batch.
#[derive(Default)]
struct NotifyBatch {
    all_zones: bool,
    zones: HashSet<String>,
}

impl NotifyBatch {
    fn add(&mut self, job: ApplyJob) {
        match job.zone_name {
            Some(name) => {
                self.zones.insert(name);
            }
            None => self.all_zones = true,
        }
    }

    async fn flush(self) {
        if self.all_zones {
            // Notifying all zones covers every per-zone entry in this batch.
            if let Err(e) = send_notify(None).await {
                log_warn!("async apply: NOTIFY failed for zone <all>: {}", e);
            }
            return;
        }
        for zone in self.zones {
            if let Err(e) = send_notify(Some(&zone)).await {
                log_warn!("async apply: NOTIFY failed for zone {}: {}", zone, e);
            }
        }
    }
}

/// Queue a NOTIFY for later delivery. Returns `false` if the worker was never
/// started, so the caller can fall back to sending inline.
pub(crate) fn enqueue_notify(zone_name: Option<&str>) -> bool {
    match APPLY_QUEUE.get() {
        Some(tx) => tx
            .send(ApplyJob {
                zone_name: zone_name.map(str::to_string),
            })
            .is_ok(),
        None => false,
    }
}
