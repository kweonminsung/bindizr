//! The NOTIFY queue behind `dns.notify.batch_ms`: committed writes enqueue a
//! NOTIFY here and return, and the worker batches a burst into one NOTIFY per
//! zone.

use std::{collections::HashSet, sync::OnceLock, time::Duration};

use bindizr_core::config;
use tokio::{
    sync::{
        mpsc::{UnboundedSender, unbounded_channel},
        watch,
    },
    task::JoinHandle,
    time::{Instant, timeout},
};

use super::send_notify;

/// A queued propagation job: send NOTIFY for one zone, or for all zones (`None`).
#[derive(Debug)]
struct NotifyJob {
    zone_name: Option<String>,
}

static NOTIFY_QUEUE: OnceLock<UnboundedSender<NotifyJob>> = OnceLock::new();

/// Set when the daemon asks the worker to flush what it holds and finish.
static NOTIFY_STOP: OnceLock<watch::Sender<bool>> = OnceLock::new();

/// Spawn the background worker that drains queued NOTIFYs, handing back its
/// task so the daemon can wait for it. First call wins; later calls are
/// no-ops. Without it, writes fall back to sending inline.
pub fn initialize_worker() -> Option<JoinHandle<()>> {
    let (tx, mut rx) = unbounded_channel::<NotifyJob>();
    if NOTIFY_QUEUE.set(tx).is_err() {
        return None;
    }
    let (stop_tx, mut stop) = watch::channel(false);
    let _ = NOTIFY_STOP.set(stop_tx);

    Some(tokio::spawn(async move {
        // Block for the first job, then batch everything that arrives within
        // the configured window into a single NOTIFY per zone.
        loop {
            let first = tokio::select! {
                job = rx.recv() => match job {
                    Some(job) => job,
                    None => break,
                },
                _ = stop.changed() => break,
            };
            let mut batch = NotifyBatch::default();
            batch.add(first);

            let window = Duration::from_millis(config::bindizr_config().dns.notify.batch_ms);
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
            // Drain anything already queued (covers a window a reload has
            // just dropped to zero, too).
            while let Ok(job) = rx.try_recv() {
                batch.add(job);
            }

            batch.flush().await;
        }

        // Refuse new jobs before flushing: an enqueue racing this shutdown
        // then fails and its caller sends inline, while `recv` still drains
        // what the channel already holds.
        rx.close();

        // A batched write was answered as soon as its NOTIFY was queued, so
        // send what is left; otherwise secondaries keep serving the old serial
        // until their own refresh timer.
        let mut last = NotifyBatch::default();
        while let Some(job) = rx.recv().await {
            last.add(job);
        }
        last.flush().await;
    }))
}

/// Ask the worker to send what it holds and finish.
pub fn stop_worker() {
    if let Some(stop) = NOTIFY_STOP.get() {
        let _ = stop.send(true);
    }
}

/// Accumulates queued jobs so a burst collapses to one NOTIFY per zone. An
/// all-zones job supersedes every per-zone job in the same batch.
#[derive(Default)]
struct NotifyBatch {
    all_zones: bool,
    zones: HashSet<String>,
}

impl NotifyBatch {
    /// Add a zone to the pending NOTIFY batch.
    fn add(&mut self, job: NotifyJob) {
        match job.zone_name {
            Some(name) => {
                self.zones.insert(name);
            }
            None => self.all_zones = true,
        }
    }

    /// Drain the pending batch and send notifications for its zones.
    async fn flush(self) {
        if !self.all_zones && self.zones.is_empty() {
            return;
        }
        if self.all_zones {
            // Notifying all zones covers every per-zone entry in this batch.
            if let Err(e) = send_notify(None).await {
                log::warn!("queued notify: NOTIFY failed for zone <all>: {}", e);
            }
            return;
        }
        for zone in self.zones {
            if let Err(e) = send_notify(Some(&zone)).await {
                log::warn!("queued notify: NOTIFY failed for zone {}: {}", zone, e);
            }
        }
    }
}

/// Queue a NOTIFY for later delivery. Returns `false` if the worker was never
/// started, so the caller can fall back to sending inline.
pub(crate) fn enqueue_notify(zone_name: Option<&str>) -> bool {
    match NOTIFY_QUEUE.get() {
        Some(tx) => tx
            .send(NotifyJob {
                zone_name: zone_name.map(str::to_string),
            })
            .is_ok(),
        None => false,
    }
}
