//! The NOTIFY queue behind `dns.notify.batch_ms`: committed writes enqueue a
//! NOTIFY here and return, and the worker batches a burst into one NOTIFY per
//! zone. The sender lives in the `Context`; the worker holds an `Arc` of it.

use std::{collections::HashSet, sync::Arc, time::Duration};

use bindizr_core::dns::name::ZoneName;
use tokio::{
    sync::{
        mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
        watch,
    },
    task::JoinHandle,
    time::{Instant, timeout},
};

use super::{NotifyTarget, send_notify};
use crate::Context;

/// A queued propagation job: send NOTIFY for one zone, or for all zones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyJob {
    zone_name: Option<ZoneName>,
}

impl NotifyJob {
    /// A job for the zones `target` names.
    pub(crate) fn new(target: NotifyTarget<'_>) -> Self {
        NotifyJob {
            zone_name: match target {
                NotifyTarget::Zone(zone_name) => Some(zone_name.clone()),
                NotifyTarget::All => None,
            },
        }
    }
}

/// The job channel: the sender goes into the `Context`, the receiver to
/// [`spawn`].
pub fn channel() -> (UnboundedSender<NotifyJob>, UnboundedReceiver<NotifyJob>) {
    unbounded_channel()
}

/// The running worker, as the daemon holds it: `stop` asks it to flush what
/// it holds and finish, handing back the task to wait for.
#[derive(Debug)]
pub struct NotifyWorker {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl NotifyWorker {
    /// Ask the worker to send what it holds and finish; await the returned
    /// task for that to be done.
    pub fn stop(self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task
    }
}

/// Spawn the background worker that drains queued NOTIFYs.
pub fn spawn(cx: Arc<Context>, mut rx: UnboundedReceiver<NotifyJob>) -> NotifyWorker {
    let (stop_tx, mut stop) = watch::channel(false);

    let task = tokio::spawn(async move {
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

            let window = Duration::from_millis(cx.config().dns.notify.batch_ms);
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

            batch.flush(&cx).await;
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
        last.flush(&cx).await;
    });

    NotifyWorker {
        task,
        stop: stop_tx,
    }
}

/// Accumulates queued jobs so a burst collapses to one NOTIFY per zone. An
/// all-zones job supersedes every per-zone job in the same batch.
#[derive(Default)]
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

    /// Drain the pending batch and send notifications for its zones.
    async fn flush(self, cx: &Context) {
        if !self.all_zones && self.zones.is_empty() {
            return;
        }
        if self.all_zones {
            // Notifying all zones covers every per-zone entry in this batch.
            if let Err(e) = send_notify(cx, NotifyTarget::All).await {
                log::warn!("queued notify: NOTIFY failed for zone <all>: {}", e);
            }
            return;
        }
        for zone in self.zones {
            if let Err(e) = send_notify(cx, NotifyTarget::Zone(&zone)).await {
                log::warn!("queued notify: NOTIFY failed for zone {}: {}", zone, e);
            }
        }
    }
}
