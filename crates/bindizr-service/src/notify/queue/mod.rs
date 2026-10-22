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
        // Remote ACK waits must not block collection of the next write batch.
        let mut tasks = JoinSet::new();

        loop {
            if *stop.borrow() {
                break;
            }

            let collect = async {
                let first = tokio::select! {
                    biased;
                    _ = stop.changed() => return None,

                    job = rx.recv() => job?,
                };
                Some(collect_batch(&cx, &mut rx, &mut stop, first).await)
            };
            tokio::pin!(collect);
            let batch = loop {
                tokio::select! {
                    batch = &mut collect => break batch,

                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = result {
                            log::warn!("queued notify: task failed: {}", error);
                        }
                    }
                }
            };
            let Some(batch) = batch else {
                break;
            };

            start_batch(&cx, batch, &mut tasks).await;
        }

        // Reject new jobs before draining so racing callers fall back to inline NOTIFY.
        rx.close();

        // Flush acknowledged writes so secondaries need not wait for their refresh timer.
        let mut last = NotifyBatch::default();

        while let Some(job) = rx.recv().await {
            last.add(job);
        }

        start_batch(&cx, last, &mut tasks).await;

        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                log::warn!("queued notify: task failed: {}", error);
            }
        }
    });

    NotifyWorker {
        task,
        stop: stop_tx,
    }
}

/// Pending zones; an all-zones job expands into the same deduplicated set.
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
async fn read_batch_deadline(cx: &Context, job: &NotifyJob) -> Instant {
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

    let mut deadline = read_batch_deadline(cx, &first).await;

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
                    deadline = deadline.min(read_batch_deadline(cx, &job).await);
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

/// Start a batch without holding collection behind an earlier ACK/retry wait.
async fn start_batch(cx: &Arc<Context>, mut batch: NotifyBatch, tasks: &mut JoinSet<()>) {
    if batch.all_zones {
        match crate::zone::list(cx).await {
            Ok(zones) => batch.zones.extend(zones.into_iter().map(|zone| zone.name)),
            Err(error) => log::warn!("queued notify: failed to list zones: {}", error),
        }
    }

    for zone in batch.zones {
        let cx = cx.clone();
        tasks.spawn(async move {
            if let Err(error) = send_notify(&cx, NotifyTarget::Zone(&zone)).await {
                log::warn!("queued notify: NOTIFY failed for zone {}: {}", zone, error);
            }
        });
    }
}

#[cfg(test)]
mod tests;
