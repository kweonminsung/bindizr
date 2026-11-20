//! Daemon state, built by `bootstrap` in dependency order and passed to service flows.

use std::sync::{Arc, OnceLock, RwLock};

use bindizr_core::config::{Config, ConfigError};
use bindizr_core::dns::name::ZoneName;
use bindizr_core::metrics::Metrics;
use bindizr_core::model::access_log::AccessLog;
use bindizr_db::{Db, PoolStats};
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::sync::{Semaphore, watch};

use crate::dns_client::notify::NotifyClient;
use crate::error::ServiceError;
use crate::notify;
use crate::notify::queue::NotifyJob;

/// Why a reload left the configuration as it was.
#[derive(Debug, Error)]
pub enum ReloadConfigError {
    #[error(transparent)]
    Load(#[from] ConfigError),
    #[error("these settings are fixed while bindizr runs, so nothing was reloaded: {}", settings.join(", "))]
    FixedSettingsChanged { settings: Vec<String> },
}

/// A refused reload is the operator's to fix.
impl From<ReloadConfigError> for ServiceError {
    /// Build an invalid-input error from the reload failure.
    fn from(error: ReloadConfigError) -> Self {
        Self::invalid_input(error)
    }
}

/// Shared service state; workers hold an `Arc`, and only their senders live here.
#[derive(Debug)]
pub struct Context {
    /// Swapped whole by `reload_config`; a reader takes a snapshot, so one
    /// request decides on one version even if a reload lands mid-way.
    config: RwLock<Arc<Config>>,
    /// The file `reload_config` re-reads. Fixed at startup: a reload changes
    /// settings, never which file they come from.
    config_path: String,
    /// Private, so data access is the service crate's alone.
    db: Db,
    metrics: Metrics,
    notify_jobs: UnboundedSender<NotifyJob>,
    notify_client: NotifyClient,
    notify_preparations: Semaphore,
    /// The access log writer's queue, bounded so a request never waits on its row.
    access_logs: Sender<AccessLog>,
    /// The scheduler's period, so a reload reaches it without waiting the
    /// old one out; zero stands the scheduler down.
    scheduler_period: watch::Sender<u64>,
    /// Set once every front end serves.
    started_at: OnceLock<DateTime<Utc>>,
}

impl Context {
    /// Assemble the daemon's state from the pieces `bootstrap` built.
    pub fn new(
        config: Config,
        config_path: String,
        db: Db,
        metrics: Metrics,
        notify_jobs: UnboundedSender<NotifyJob>,
        access_logs: Sender<AccessLog>,
        scheduler_period: watch::Sender<u64>,
    ) -> Self {
        Self {
            config: RwLock::new(Arc::new(config)),
            config_path,
            db,
            metrics,
            notify_jobs,
            notify_client: NotifyClient::default(),
            notify_preparations: Semaphore::new(notify::CONCURRENT_PREPARATIONS),
            access_logs,
            scheduler_period,
            started_at: OnceLock::new(),
        }
    }

    /// Snapshot the configuration for one decision; discard it afterward so
    /// later decisions can observe reloads.
    pub fn config(&self) -> Arc<Config> {
        self.config
            .read()
            .expect("Bindizr configuration lock is poisoned")
            .clone()
    }

    /// Return the file the configuration came from.
    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    /// Read the configuration file again, refusing one whose fixed settings
    /// differ from the running one; nothing changes until `set_config`.
    pub fn load_config(&self) -> Result<Config, ReloadConfigError> {
        let next = Config::load(&self.config_path)?;
        let fixed = self.config().fixed_settings_changed(&next);
        if !fixed.is_empty() {
            return Err(ReloadConfigError::FixedSettingsChanged { settings: fixed });
        }
        Ok(next)
    }

    /// Replace configuration and report changed sections; the caller updates logging and scheduling.
    pub fn set_config(&self, next: Config) -> Vec<String> {
        let mut stored = self
            .config
            .write()
            .expect("Bindizr configuration lock is poisoned");
        let changed = stored.changed_settings(&next);
        *stored = Arc::new(next);

        changed
    }

    /// Return the database every query runs on.
    pub(crate) fn db(&self) -> &Db {
        &self.db
    }

    /// Return the service's bounded key/address preparation queue.
    pub(crate) fn notify_preparations(&self) -> &Semaphore {
        &self.notify_preparations
    }

    /// Return the shared NOTIFY sockets and their active exchanges.
    pub(crate) fn notify_client(&self) -> &NotifyClient {
        &self.notify_client
    }

    /// Return the daemon's metrics registry.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Return the pool's occupancy, for the metrics scrape.
    pub fn db_stats(&self) -> PoolStats {
        self.db.stats()
    }

    /// Return the moment the daemon began serving, absent while it is still starting.
    pub fn started_at(&self) -> Option<DateTime<Utc>> {
        self.started_at.get().copied()
    }

    /// Stamp the moment every front end came up; the first call wins, and
    /// the started-at gauge publishes the same moment.
    pub fn set_started_at(&self, at: DateTime<Utc>) {
        if self.started_at.set(at).is_ok() {
            self.metrics.started_at_seconds.set(at.timestamp() as f64);
        }
    }

    /// Queue a NOTIFY to send later. `false` once the worker has stopped,
    /// so the caller can fall back to sending inline.
    pub(crate) fn enqueue_notify(&self, zone_name: &ZoneName) -> bool {
        self.notify_jobs.send(NotifyJob::new(zone_name)).is_ok()
    }

    /// Queue an access log row for the writer without waiting. `false` when
    /// the queue is full or the writer has stopped, and the row is dropped.
    pub(crate) fn enqueue_access_log(&self, log: AccessLog) -> bool {
        self.access_logs.try_send(log).is_ok()
    }

    /// Hand the scheduler its period after a reload; an unchanged value is
    /// not sent, since it must not pull the next pass forward.
    pub fn set_scheduler_period(&self, interval_secs: u64) {
        if *self.scheduler_period.borrow() != interval_secs {
            let _ = self.scheduler_period.send(interval_secs);
        }
    }
}
