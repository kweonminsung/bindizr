//! The periodic scheduler pass: history and log retention, signature refresh, and
//! the rollover steps that advance on deadlines rather than operator action.

use std::sync::Arc;

use bindizr_core::metrics::SchedulerResult;
use bindizr_core::model::dnssec_key::{DnssecKeyRole, DnssecKeyState};
use bindizr_core::model::zone::ZoneId;
use chrono::{Duration, Utc};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time;
use tokio::time::{Interval, MissedTickBehavior};

use crate::dnssec::maintenance;
use crate::zone::history;
use crate::{Context, notify};

/// A scheduler task whose current pass finishes before shutdown returns.
#[derive(Debug)]
pub struct SchedulerWorker {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl SchedulerWorker {
    /// Stop starting passes and return the current pass's task to await.
    pub fn stop(self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task
    }
}

/// Start the periodic scheduler on its own task. A zero period leaves the
/// worker idle until a reload names one.
pub fn spawn(cx: Arc<Context>, mut period_rx: watch::Receiver<u64>) -> SchedulerWorker {
    let mut period = *period_rx.borrow();

    if period == 0 {
        log::info!("Scheduler disabled by dns.scheduler_interval_secs = 0");
    }

    let (stop_tx, mut stop) = watch::channel(false);

    let task = tokio::spawn(async move {
        let mut interval = scheduler_interval(period);

        loop {
            if *stop.borrow() {
                break;
            }

            tokio::select! {
                biased;
                _ = stop.changed() => break,

                _ = interval.tick(), if period != 0 => {}

                changed = period_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }

                    // Rebuild here rather than after the old period elapses,
                    // which a shortened interval would otherwise wait out.
                    let reloaded = *period_rx.borrow_and_update();

                    if reloaded != period {
                        period = reloaded;
                        interval = scheduler_interval(period);
                    }

                    continue;
                }
            }

            // A panic in the pass would otherwise unwind the scheduler itself.
            let pass_cx = cx.clone();

            if let Err(error) =
                tokio::spawn(async move { run_scheduler_pass(&pass_cx).await }).await
            {
                log::error!("Scheduler pass did not finish: {error:?}");
                cx.metrics()
                    .track_dnssec_scheduler(SchedulerResult::Panicked);
            }
        }
    });

    SchedulerWorker {
        task,
        stop: stop_tx,
    }
}

/// Create the scheduler timer; a zero period never ticks, and `spawn` guards
/// the arm so a disabled scheduler waits only for a reload.
fn scheduler_interval(period_secs: u64) -> Interval {
    let mut interval = time::interval(time::Duration::from_secs(period_secs.max(1)));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// Run one scheduler pass: journal retention, signature refresh, and rollover
/// advancement. Failures are logged, never fatal.
async fn run_scheduler_pass(cx: &Context) {
    let config = cx.config();
    let mut failed = false;

    // Bound retained IXFR and rollback history before maintaining signed zones,
    // one zone per transaction under its lock, like every other step here.
    let zone_max_days = config.history.max_days;

    if zone_max_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(zone_max_days));

        match bindizr_db::zone::list_all(cx.db()).await {
            Ok(zones) => {
                let (mut journal_rows, mut version_rows) = (0u64, 0u64);

                for zone in zones {
                    match history::prune_by_zone_id(cx, zone.id, cutoff).await {
                        Ok(pruned) => {
                            journal_rows += pruned.journal_rows;
                            version_rows += pruned.version_rows;
                        }
                        Err(error) => {
                            failed = true;
                            log::error!(
                                "Zone history pruning for zone id {} failed: {error:?}",
                                zone.id
                            );
                        }
                    }
                }

                cx.metrics().track_pruned_rows(journal_rows, version_rows);

                if journal_rows > 0 || version_rows > 0 {
                    log::info!("Pruned {journal_rows} journal and {version_rows} version rows");
                }
            }
            Err(error) => {
                failed = true;
                log::error!("Zone history pruning scan failed: {error:?}");
            }
        }
    }

    // The audit log has no row lock to take: one statement bounds it.
    let audit_max_days = config.audit_log.max_days;

    if audit_max_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(audit_max_days));

        match bindizr_db::audit_log::prune_older_than(cx.db(), cutoff).await {
            Ok(pruned) => {
                cx.metrics().track_pruned_audit_log_rows(pruned);
                if pruned > 0 {
                    log::info!("Pruned {pruned} audit log rows");
                }
            }
            Err(error) => {
                failed = true;
                log::error!("Audit log pruning failed: {error:?}");
            }
        }
    }

    // One statement bounds the access log too.
    let access_max_days = config.access_log.max_days;

    if access_max_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(access_max_days));

        match bindizr_db::access_log::prune_older_than(cx.db(), cutoff).await {
            Ok(pruned) => {
                cx.metrics().track_pruned_access_log_rows(pruned);
                if pruned > 0 {
                    log::info!("Pruned {pruned} access log rows");
                }
            }
            Err(error) => {
                failed = true;
                log::error!("Access log pruning failed: {error:?}");
            }
        }
    }

    // One statement bounds the transfer log too; the newest row of each
    // client address and zone outlives the cutoff as its last transfer.
    let transfer_max_days = config.transfer_log.max_days;

    if transfer_max_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(transfer_max_days));

        match bindizr_db::transfer_log::prune_older_than(cx.db(), cutoff).await {
            Ok(pruned) => {
                cx.metrics().track_pruned_transfer_log_rows(pruned);
                if pruned > 0 {
                    log::info!("Pruned {pruned} transfer log rows");
                }
            }
            Err(error) => {
                failed = true;
                log::error!("Transfer log pruning failed: {error:?}");
            }
        }
    }

    // Refresh expiring signatures even when the zone's user records have not changed.
    match bindizr_db::dnssec_record::list_zone_ids_expiring_within_refresh(cx.db(), Utc::now())
        .await
    {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match maintenance::resign_zone_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Re-signed zone {zone_name} ahead of signature expiry");
                        notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failed = true;
                        log::error!("Re-signing zone id {zone_id} failed: {error:?}");
                    }
                }
            }
        }
        Err(error) => {
            failed = true;
            log::error!("Re-signing scan failed: {error:?}");
        }
    }

    // ZSK rollover needs no parent interaction, so a policy lifetime lets
    // the scheduler start it too; CSK rollover stays the operator's.
    match bindizr_db::dnssec_key::list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
        cx.db(),
        DnssecKeyRole::Zsk,
        DnssecKeyState::Active,
        Utc::now(),
    )
    .await
    {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match maintenance::start_zsk_rollover_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Started scheduled ZSK rollover for zone {zone_name}");
                        notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failed = true;
                        log::error!(
                            "Scheduled ZSK rollover for zone id {zone_id} failed: {error:?}"
                        );
                    }
                }
            }
        }
        Err(error) => {
            failed = true;
            log::error!("ZSK lifetime scan failed: {error:?}");
        }
    }

    // The hold-down stamped at publication is the only gate ZSK promotion has.
    match bindizr_db::dnssec_key::list_by_state_eligible_before(
        cx.db(),
        DnssecKeyState::Published,
        Utc::now(),
    )
    .await
    {
        Ok(keys) => {
            // Keys arrive ordered by zone id, so dedup() leaves one entry per zone.
            let mut zone_ids: Vec<ZoneId> = keys
                .iter()
                .filter(|key| key.role == DnssecKeyRole::Zsk)
                .map(|key| key.zone_id)
                .collect();
            zone_ids.dedup();

            for zone_id in zone_ids {
                match maintenance::promote_zsks_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Promoted pre-published ZSK for zone {zone_name}");
                        notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failed = true;
                        log::error!("ZSK promotion for zone id {zone_id} failed: {error:?}");
                    }
                }
            }

            // SEP promotion requires parent DS confirmation; CDS-aware parents
            // may install the published DS automatically.
            let mut zone_ids: Vec<ZoneId> = keys
                .iter()
                .filter(|key| key.role.is_sep())
                .map(|key| key.zone_id)
                .collect();
            zone_ids.dedup();

            for zone_id in zone_ids {
                match maintenance::promote_sep_keys_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!(
                            "Promoted pre-published SEP key for zone {zone_name}: the parent serves its DS"
                        );
                        notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failed = true;
                        log::error!("SEP key promotion for zone id {zone_id} failed: {error:?}");
                    }
                }
            }
        }
        Err(error) => {
            failed = true;
            log::error!("Rollover promotion scan failed: {error:?}");
        }
    }

    // Remove retired keys after the hold-down for cached signed data has elapsed.
    match bindizr_db::dnssec_key::list_by_state_eligible_before(
        cx.db(),
        DnssecKeyState::Retired,
        Utc::now(),
    )
    .await
    {
        Ok(keys) => {
            // Keys arrive ordered by zone id, so dedup() leaves one entry per zone.
            let mut zone_ids: Vec<ZoneId> = keys.iter().map(|key| key.zone_id).collect();
            zone_ids.dedup();

            for zone_id in zone_ids {
                match maintenance::prune_retired_keys_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Removed retired DNSSEC key(s) for zone {zone_name}");
                        notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        failed = true;
                        log::error!("Retired-key removal for zone id {zone_id} failed: {error:?}");
                    }
                }
            }
        }
        Err(error) => {
            failed = true;
            log::error!("Retired-key scan failed: {error:?}");
        }
    }

    cx.metrics().track_dnssec_scheduler(if failed {
        SchedulerResult::Failed
    } else {
        SchedulerResult::Ok
    });
}

#[cfg(test)]
mod tests;
