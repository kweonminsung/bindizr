//! Coalesce committed writes into NOTIFY batches bounded by SOA REFRESH.

use std::{collections::HashSet, sync::Arc, time::Duration};

use bindizr_core::dns::{CATALOG_SOA_REFRESH, name::ZoneName};
use tokio::{
    sync::{mpsc::UnboundedReceiver, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until},
};

use super::{NotifyTarget, send_notify};
use crate::Context;

/// A queued propagation job: send NOTIFY for one zone, or for all zones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyJob {
    zone_name: Option<ZoneName>,
    enqueued_at: Instant,
}

impl NotifyJob {
    /// A job for the zones `target` names.
    pub(crate) fn new(target: NotifyTarget<'_>) -> Self {
        NotifyJob {
            zone_name: match target {
                NotifyTarget::Zone(zone_name) => Some(zone_name.clone()),
                NotifyTarget::All => None,
            },
            enqueued_at: Instant::now(),
        }
    }
}

/// A NOTIFY worker that flushes pending jobs on shutdown.
#[derive(Debug)]
pub struct NotifyWorker {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl NotifyWorker {
    /// Request a final flush and return the worker task to await.
    pub fn stop(self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task
    }
}

/// Spawn the background worker that drains queued NOTIFYs.
pub fn spawn(cx: Arc<Context>, mut rx: UnboundedReceiver<NotifyJob>) -> NotifyWorker {
    let (stop_tx, mut stop) = watch::channel(false);

    let task = tokio::spawn(async move {
        loop {
            if *stop.borrow() {
                break;
            }
            let first = tokio::select! {
                biased;
                _ = stop.changed() => break,
                job = rx.recv() => match job {
                    Some(job) => job,
                    None => break,
                },
            };
            let batch = collect_batch(&cx, &mut rx, &mut stop, first).await;
            send_batch(&cx, batch).await;
        }

        // Reject new jobs before draining so racing callers fall back to inline NOTIFY.
        rx.close();

        // Flush acknowledged writes so secondaries need not wait for their refresh timer.
        let mut last = NotifyBatch::default();
        while let Some(job) = rx.recv().await {
            last.add(job);
        }
        send_batch(&cx, last).await;
    });

    NotifyWorker {
        task,
        stop: stop_tx,
    }
}

/// Pending zones; an all-zones job supersedes individual entries.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct NotifyBatch {
    all_zones: bool,
    zones: HashSet<ZoneName>,
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
}

/// Bound intentional delay by SOA REFRESH, measured from enqueue time
/// (RFC 1996, Section 4.3). Failed lookups send immediately.
async fn batch_deadline(cx: &Context, job: &NotifyJob) -> Instant {
    let config = cx.config();
    let window = Duration::from_millis(config.dns.notify.batch_ms);
    if window.is_zero() {
        return job.enqueued_at;
    }
    let refresh = match &job.zone_name {
        Some(name) if name == &config.dns.catalog_zone_name => Ok(CATALOG_SOA_REFRESH),
        Some(name) => crate::zone::lookup_by_name(cx, name)
            .await
            .map(|zone| zone.refresh),
        None => crate::zone::list(cx).await.map(|zones| {
            zones
                .into_iter()
                .map(|zone| zone.refresh)
                .min()
                .unwrap_or(CATALOG_SOA_REFRESH)
        }),
    };
    let delay = match refresh {
        Ok(refresh) => window.min(Duration::from_secs(u64::from(refresh.as_secs()))),
        Err(error) => {
            log::warn!(
                "queued notify: failed to read SOA REFRESH; sending immediately: {}",
                error
            );
            Duration::ZERO
        }
    };
    job.enqueued_at + delay
}

/// Coalesce jobs until the earliest deadline or shutdown.
async fn collect_batch(
    cx: &Context,
    rx: &mut UnboundedReceiver<NotifyJob>,
    stop: &mut watch::Receiver<bool>,
    first: NotifyJob,
) -> NotifyBatch {
    let mut batch = NotifyBatch::default();
    let mut deadline = batch_deadline(cx, &first).await;
    batch.add(first);
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = sleep_until(deadline) => break,
            job = rx.recv() => match job {
                Some(job) => {
                    // Later writes may shorten the window, never extend it.
                    deadline = deadline.min(batch_deadline(cx, &job).await);
                    batch.add(job);
                }
                None => break,
            },
        }
    }
    // Drain a fixed backlog so producers cannot postpone a ready batch.
    for _ in 0..rx.len() {
        if let Ok(job) = rx.try_recv() {
            batch.add(job);
        }
    }
    batch
}

/// Send one NOTIFY per pending zone, concurrently.
async fn send_batch(cx: &Arc<Context>, batch: NotifyBatch) {
    if !batch.all_zones && batch.zones.is_empty() {
        return;
    }
    if batch.all_zones {
        if let Err(e) = send_notify(cx, NotifyTarget::All).await {
            log::warn!("queued notify: NOTIFY failed for zone <all>: {}", e);
        }
        return;
    }
    let mut tasks = JoinSet::new();
    for zone in batch.zones {
        let cx = cx.clone();
        tasks.spawn(async move {
            if let Err(e) = send_notify(&cx, NotifyTarget::Zone(&zone)).await {
                log::warn!("queued notify: NOTIFY failed for zone {}: {}", zone, e);
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            log::warn!("queued notify: task failed: {}", error);
        }
    }
}

#[cfg(test)]
mod tests;
