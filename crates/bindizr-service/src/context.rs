//! The daemon's state, built once by `bootstrap` in dependency order and
//! passed by reference to every service function: the configuration
//! snapshot, the database, the metrics, the senders of the NOTIFY queue and
//! the DNSSEC scheduler, and the moment the daemon began serving.

use std::sync::{Arc, OnceLock, RwLock};

use bindizr_core::{
    config::{Config, ConfigError},
    metrics::Metrics,
};
use bindizr_db::{Db, PoolStats};
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::{mpsc::UnboundedSender, watch};

use crate::{error::ServiceError, notify::queue::NotifyJob};

/// Why a reload left the configuration as it was.
#[derive(Debug, Error)]
pub enum ReloadConfigError {
    #[error(transparent)]
    Load(#[from] ConfigError),
    #[error("Bindizr configuration lock is poisoned")]
    Poisoned,
    #[error("these settings are fixed while bindizr runs, so nothing was reloaded: {}", settings.join(", "))]
    FixedSettingsChanged { settings: Vec<String> },
}

/// A refused reload is the operator's to fix, except a poisoned lock.
impl From<ReloadConfigError> for ServiceError {
    /// Classify the reload failure for the error payload.
    fn from(err: ReloadConfigError) -> Self {
        match err {
            ReloadConfigError::Poisoned => ServiceError::Internal {
                message: err.to_string(),
                source: Some(Box::new(err)),
            },
            other => ServiceError::invalid_input(other),
        }
    }
}

/// What every service function takes first. The workers that need it back
/// (the NOTIFY queue, the scheduler) are spawned after it with an `Arc` of
/// their own; only their senders live here.
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
        scheduler_period: watch::Sender<u64>,
    ) -> Self {
        Context {
            config: RwLock::new(Arc::new(config)),
            config_path,
            db,
            metrics,
            notify_jobs,
            scheduler_period,
            started_at: OnceLock::new(),
        }
    }

    /// A snapshot of the configuration. A reload is invisible to a snapshot
    /// already taken, so hold one for as long as a single decision takes and
    /// no longer.
    pub fn config(&self) -> Arc<Config> {
        self.config
            .read()
            .expect("Bindizr configuration lock is poisoned")
            .clone()
    }

    /// The file the configuration came from.
    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    /// Re-read the configuration file and replace the held one, returning the
    /// settings that changed. A setting a running process cannot adopt is
    /// refused rather than stored. The caller applies what only it can: the
    /// logger's level, the scheduler's period.
    pub fn reload_config(&self) -> Result<Vec<String>, ReloadConfigError> {
        let next = Config::load(&self.config_path)?;

        let mut stored = self
            .config
            .write()
            .map_err(|_| ReloadConfigError::Poisoned)?;
        let fixed = stored.fixed_settings_changed(&next);
        if !fixed.is_empty() {
            return Err(ReloadConfigError::FixedSettingsChanged { settings: fixed });
        }

        let changed = stored.changed_settings(&next);
        *stored = Arc::new(next);
        Ok(changed)
    }

    /// The database every query runs on.
    pub(crate) fn db(&self) -> &Db {
        &self.db
    }

    /// The daemon's metrics registry.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The pool's occupancy, for the metrics scrape.
    pub fn db_stats(&self) -> PoolStats {
        self.db.stats()
    }

    /// The moment the daemon began serving, absent while it is still starting.
    pub fn started_at(&self) -> Option<DateTime<Utc>> {
        self.started_at.get().copied()
    }

    /// Record the moment every front end came up; the first call wins, and
    /// the started-at gauge publishes the same moment.
    pub fn set_started_at(&self, at: DateTime<Utc>) {
        if self.started_at.set(at).is_ok() {
            self.metrics.started_at_seconds.set(at.timestamp() as f64);
        }
    }

    /// Queue a NOTIFY for later delivery. `false` once the worker has stopped,
    /// so the caller can fall back to sending inline.
    pub(crate) fn enqueue_notify(&self, zone_name: Option<&str>) -> bool {
        self.notify_jobs.send(NotifyJob::new(zone_name)).is_ok()
    }

    /// Hand the scheduler its period after a reload; an unchanged value is
    /// not sent, since it must not pull the next pass forward.
    pub fn set_scheduler_period(&self, interval_secs: u64) {
        if *self.scheduler_period.borrow() != interval_secs {
            let _ = self.scheduler_period.send(interval_secs);
        }
    }
}
