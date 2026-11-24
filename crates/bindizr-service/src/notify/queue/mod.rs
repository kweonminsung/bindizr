//! Coalesce committed writes into NOTIFY batches bounded by SOA REFRESH.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bindizr_core::dns::name::ZoneName;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::watch;
use tokio::sync::watch::{Receiver, Sender};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time;
use tokio::time::Instant;

use crate::{Context, notify, zone};

/// A queued propagation job: send NOTIFY for one zone a committed write changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyJob {
    zone_name: ZoneName,
    enqueued_at: Instant,
}

impl NotifyJob {
    /// Create a job for `zone_name`, stamped now.
    pub(crate) fn new(zone_name: &ZoneName) -> Self {
        Self {
            zone_name: zone_name.clone(),
            enqueued_at: Instant::now(),
        }
    }
}

/// A NOTIFY worker that flushes pending jobs on shutdown.
#[derive(Debug)]
pub struct NotifyWorker {
    task: JoinHandle<()>,
    stop: Sender<bool>,
}

impl NotifyWorker {
    /// Request a final flush and return the worker task to await.
    pub fn stop(self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task
    }
}

/// Spawn the background worker that drains queued NOTIFYs.
pub fn spawn(cx: Arc<Context>, mut jobs: UnboundedReceiver<NotifyJob>) -> NotifyWorker {
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

                    job = jobs.recv() => job?,
                };
                Some(collect_batch(&cx, &mut jobs, &mut stop, first).await)
            };
            tokio::pin!(collect);
            let zone_names = loop {
                tokio::select! {
                    zone_names = &mut collect => break zone_names,

                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = result {
                            log::warn!("queued notify: task failed: {error}");
                        }
                    }
                }
            };
            let Some(zone_names) = zone_names else {
                break;
            };

            start_batch(&cx, zone_names, &mut tasks).await;
        }

        // Reject new jobs before draining so racing callers fall back to inline NOTIFY.
        jobs.close();

        // Flush acknowledged writes so secondaries need not wait for their refresh timer.
        let mut last = HashSet::new();

        while let Some(job) = jobs.recv().await {
            last.insert(job.zone_name);
        }

        start_batch(&cx, last, &mut tasks).await;

        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                log::warn!("queued notify: task failed: {error}");
            }
        }
    });

    NotifyWorker {
        task,
        stop: stop_tx,
    }
}

/// Look up the batch deadline: intentional delay is bounded by SOA REFRESH,
/// measured from enqueue time (RFC 1996, Section 4.3). Failed lookups send immediately.
async fn lookup_batch_deadline(cx: &Context, job: &NotifyJob) -> Instant {
    let config = cx.config();
    let window = Duration::from_millis(config.dns.notify.batch_ms);

    if window.is_zero() {
        return job.enqueued_at;
    }

    let refresh = if job.zone_name == config.dns.catalog_zone_name {
        Ok(zone::CATALOG_SOA_REFRESH)
    } else {
        zone::lookup_by_name(cx, &job.zone_name)
            .await
            .map(|zone| zone.refresh)
    };
    let delay = match refresh {
        Ok(refresh) => window.min(Duration::from_secs(u64::from(refresh.as_secs()))),
        Err(error) => {
            // A zone gone since its write is ordinary; a failed read is a fault.
            if error.code().is_internal() {
                log::error!(
                    "queued notify: failed to read SOA REFRESH; sending immediately: {error:?}"
                );
            } else {
                log::warn!(
                    "queued notify: failed to read SOA REFRESH; sending immediately: {error:?}"
                );
            }

            Duration::ZERO
        }
    };

    job.enqueued_at + delay
}

/// Coalesce jobs until the earliest deadline or shutdown.
async fn collect_batch(
    cx: &Context,
    jobs: &mut UnboundedReceiver<NotifyJob>,
    stop: &mut Receiver<bool>,
    first: NotifyJob,
) -> HashSet<ZoneName> {
    let mut zone_names = HashSet::new();

    let mut deadline = lookup_batch_deadline(cx, &first).await;

    zone_names.insert(first.zone_name);

    loop {
        if *stop.borrow() {
            break;
        }

        tokio::select! {
            biased;
            _ = stop.changed() => break,

            () = time::sleep_until(deadline) => break,

            job = jobs.recv() => match job {
                Some(job) => {
                    // Later writes may shorten the window, never extend it.
                    deadline = deadline.min(lookup_batch_deadline(cx, &job).await);
                    zone_names.insert(job.zone_name);
                }
                None => break,
            },
        }
    }

    // Drain a fixed backlog so producers cannot postpone a ready batch.
    for _ in 0..jobs.len() {
        if let Ok(job) = jobs.try_recv() {
            zone_names.insert(job.zone_name);
        }
    }

    zone_names
}

/// Start a batch without holding collection behind an earlier ACK/retry wait.
async fn start_batch(cx: &Arc<Context>, zone_names: HashSet<ZoneName>, tasks: &mut JoinSet<()>) {
    for zone_name in zone_names {
        let cx = cx.clone();
        tasks.spawn(async move {
            if let Err(error) = notify::send_zone_notify(&cx, &zone_name).await {
                if error.is_server_fault() {
                    log::error!("queued notify: NOTIFY failed for zone {zone_name}: {error:?}");
                } else {
                    log::warn!("queued notify: NOTIFY failed for zone {zone_name}: {error:?}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests;
