//! The periodic scheduler pass: journal retention, signature refresh, and
//! the rollover steps that advance on deadlines rather than operator action.

mod steps;

use std::sync::Arc;

use bindizr_core::{metrics::SchedulerResult, model::zone::ZoneId};
use chrono::{Duration, Utc};
use tokio::sync::watch;

use self::steps::{
    promote_sep_keys_by_zone_id, promote_zsks_by_zone_id, prune_retired_keys_by_zone_id,
    prune_zone_history_by_zone_id, resign_zone_by_zone_id, start_zsk_rollover_by_zone_id,
};
use crate::{
    Context,
    model::dnssec_key::{DnssecKeyRole, DnssecKeyState},
};

/// The period channel: the sender lives in the `Context` so a reload reaches
/// the worker, the receiver goes to [`spawn`]. Zero stands the worker down.
pub fn channel(interval_secs: u64) -> (watch::Sender<u64>, watch::Receiver<u64>) {
    watch::channel(interval_secs)
}

/// Start the periodic scheduler on its own task. A zero period leaves the
/// worker idle until a reload names one.
pub fn spawn(cx: Arc<Context>, mut period_rx: watch::Receiver<u64>) {
    let mut period = *period_rx.borrow();
    if period == 0 {
        log::info!("Scheduler disabled by dns.scheduler_interval_secs = 0");
    }
    tokio::spawn(async move {
        let mut interval = scheduler_interval(period);
        loop {
            tokio::select! {
                _ = interval.tick(), if period != 0 => {}
                Ok(()) = period_rx.changed() => {
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
            if let Err(e) = tokio::spawn(async move { run_scheduler_pass(&pass_cx).await }).await {
                log::error!("DNSSEC scheduler pass did not finish: {}", e);
                cx.metrics()
                    .track_dnssec_scheduler(SchedulerResult::Panicked);
            }
        }
    });
}

/// Create the scheduler timer; a zero period never ticks, and `spawn` guards
/// the arm so a disabled scheduler waits only for a reload.
fn scheduler_interval(period_secs: u64) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(period_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// One scheduler pass: journal retention, signature refresh, and rollover
/// advancement. Failures are logged, never fatal.
async fn run_scheduler_pass(cx: &Context) {
    let config = cx.config();
    let mut failed = false;

    // Bound retained IXFR and rollback history before maintaining signed zones,
    // one zone per transaction under its lock, like every other step here.
    let retention_days = config.dns.zone_history_retention_days;
    if retention_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
        match bindizr_db::zone::list_all(cx.db()).await {
            Ok(zones) => {
                let (mut journal_rows, mut version_rows) = (0u64, 0u64);
                for zone in zones {
                    match prune_zone_history_by_zone_id(cx, zone.id, cutoff).await {
                        Ok(pruned) => {
                            journal_rows += pruned.journal_rows;
                            version_rows += pruned.version_rows;
                        }
                        Err(e) => {
                            failed = true;
                            log::error!(
                                "Zone history pruning for zone id {} failed: {}",
                                zone.id,
                                e
                            )
                        }
                    }
                }
                cx.metrics().track_pruned_rows(journal_rows, version_rows);
                if journal_rows > 0 || version_rows > 0 {
                    log::info!(
                        "Pruned {} journal and {} version rows",
                        journal_rows,
                        version_rows
                    );
                }
            }
            Err(e) => {
                failed = true;
                log::error!("Zone history pruning scan failed: {}", e)
            }
        }
    }

    // Refresh expiring signatures even when the zone's user records have not changed.
    match bindizr_db::dnssec_record::list_zone_ids_expiring_within_refresh(cx.db(), Utc::now())
        .await
    {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match resign_zone_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Re-signed zone {} ahead of signature expiry", zone_name);
                        crate::notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log::error!("Re-signing zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log::error!("Re-signing scan failed: {}", e)
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
                match start_zsk_rollover_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Started scheduled ZSK rollover for zone {}", zone_name);
                        crate::notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log::error!(
                            "Scheduled ZSK rollover for zone id {} failed: {}",
                            zone_id,
                            e
                        )
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log::error!("ZSK lifetime scan failed: {}", e)
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
                match promote_zsks_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Promoted pre-published ZSK for zone {}", zone_name);
                        crate::notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log::error!("ZSK promotion for zone id {} failed: {}", zone_id, e)
                    }
                }
            }

            // A SEP key also needs its DS at the parent, so this asks. A
            // parent that consumes the CDS bindizr publishes installs it
            // itself.
            let mut zone_ids: Vec<ZoneId> = keys
                .iter()
                .filter(|key| key.role.is_sep())
                .map(|key| key.zone_id)
                .collect();
            zone_ids.dedup();
            for zone_id in zone_ids {
                match promote_sep_keys_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!(
                            "Promoted pre-published SEP key for zone {}: the parent serves its DS",
                            zone_name
                        );
                        crate::notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log::error!("SEP key promotion for zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log::error!("Rollover promotion scan failed: {}", e)
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
                match prune_retired_keys_by_zone_id(cx, zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Removed retired DNSSEC key(s) for zone {}", zone_name);
                        crate::notify::notify_after_update(cx, &zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log::error!("Retired-key removal for zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log::error!("Retired-key scan failed: {}", e)
        }
    }

    cx.metrics().track_dnssec_scheduler(if failed {
        SchedulerResult::Failed
    } else {
        SchedulerResult::Ok
    });
}
