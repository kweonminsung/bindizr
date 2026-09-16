//! The periodic maintenance task: journal retention, signature refresh, and
//! the rollover steps that advance on deadlines rather than operator action.

mod steps;

use std::sync::OnceLock;

use bindizr_core::{
    config::bindizr_config,
    metrics::{MaintenanceResult, track_dnssec_maintenance, track_pruned_rows},
};
use chrono::{Duration, Utc};

use self::steps::{
    promote_sep_keys_by_zone_id, promote_zsks_by_zone_id, prune_zone_history_by_zone_id,
    remove_retired_keys_by_zone_id, resign_zone_by_zone_id, start_zsk_rollover_by_zone_id,
};
use super::notify_zone;
use crate::{
    model::dnssec_key::{DnssecKeyRole, DnssecKeyState},
    repository::RepositoryService,
};

static MAINTENANCE_SCHEDULER: OnceLock<()> = OnceLock::new();

/// Start the periodic maintenance task. Called once from the daemon after
/// the database is initialized; later calls are no-ops. A zero
/// `dns.scheduler_interval_secs` leaves this instance without one.
pub fn init_maintenance_scheduler() {
    let interval_secs = bindizr_config().dns.scheduler_interval_secs;
    if interval_secs == 0 {
        log::info!("Maintenance scheduler disabled by dns.scheduler_interval_secs = 0");
        return;
    }
    if MAINTENANCE_SCHEDULER.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut period = interval_secs;
        let mut interval = maintenance_interval(period);
        loop {
            interval.tick().await;
            // A reload can change the period, or stand this instance down.
            let configured = bindizr_config().dns.scheduler_interval_secs;
            if configured == 0 {
                continue;
            }
            if configured != period {
                period = configured;
                interval = maintenance_interval(period);
                continue;
            }
            // A panic in the pass would otherwise unwind the scheduler itself.
            if let Err(e) = tokio::spawn(run_maintenance_pass()).await {
                log::error!("DNSSEC maintenance pass did not finish: {}", e);
                track_dnssec_maintenance(MaintenanceResult::Panic);
            }
        }
    });
}

/// Create the configured DNSSEC maintenance timer.
fn maintenance_interval(period_secs: u64) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(period_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// One scheduler pass: journal retention, signature refresh, and rollover
/// advancement. Failures are logged, never fatal.
async fn run_maintenance_pass() {
    let config = bindizr_config();
    let mut failed = false;

    // Bound retained IXFR and rollback history before maintaining signed zones,
    // one zone per transaction under its lock, like every other step here.
    let retention_days = config.dns.zone_history_retention_days;
    if retention_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
        match RepositoryService::list_zones().await {
            Ok(zones) => {
                let (mut journal_rows, mut version_rows) = (0u64, 0u64);
                for zone in zones {
                    match prune_zone_history_by_zone_id(zone.id, cutoff).await {
                        Ok((journal, versions)) => {
                            journal_rows += journal;
                            version_rows += versions;
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
                track_pruned_rows(journal_rows, version_rows);
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
    match RepositoryService::list_rrsig_zone_ids_expiring_within_refresh(Utc::now()).await {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match resign_zone_by_zone_id(zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Re-signed zone {} ahead of signature expiry", zone_name);
                        notify_zone(&zone_name).await;
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
    match RepositoryService::list_dnssec_key_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
        DnssecKeyRole::Zsk,
        DnssecKeyState::Active,
        Utc::now(),
    )
    .await
    {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match start_zsk_rollover_by_zone_id(zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Started scheduled ZSK rollover for zone {}", zone_name);
                        notify_zone(&zone_name).await;
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
    match RepositoryService::list_dnssec_keys_by_state_eligible_before(
        DnssecKeyState::Published,
        Utc::now(),
    )
    .await
    {
        Ok(keys) => {
            // Keys arrive ordered by zone id, so dedup() leaves one entry per zone.
            let mut zone_ids: Vec<i32> = keys
                .iter()
                .filter(|key| key.role == DnssecKeyRole::Zsk)
                .map(|key| key.zone_id)
                .collect();
            zone_ids.dedup();
            for zone_id in zone_ids {
                match promote_zsks_by_zone_id(zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Promoted pre-published ZSK for zone {}", zone_name);
                        notify_zone(&zone_name).await;
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
            let mut zone_ids: Vec<i32> = keys
                .iter()
                .filter(|key| key.role.is_sep())
                .map(|key| key.zone_id)
                .collect();
            zone_ids.dedup();
            for zone_id in zone_ids {
                match promote_sep_keys_by_zone_id(zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!(
                            "Promoted pre-published SEP key for zone {}: the parent serves its DS",
                            zone_name
                        );
                        notify_zone(&zone_name).await;
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
    match RepositoryService::list_dnssec_keys_by_state_eligible_before(
        DnssecKeyState::Retired,
        Utc::now(),
    )
    .await
    {
        Ok(keys) => {
            // Keys arrive ordered by zone id, so dedup() leaves one entry per zone.
            let mut zone_ids: Vec<i32> = keys.iter().map(|key| key.zone_id).collect();
            zone_ids.dedup();
            for zone_id in zone_ids {
                match remove_retired_keys_by_zone_id(zone_id).await {
                    Ok(Some(zone_name)) => {
                        log::info!("Removed retired DNSSEC key(s) for zone {}", zone_name);
                        notify_zone(&zone_name).await;
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

    track_dnssec_maintenance(if failed {
        MaintenanceResult::Error
    } else {
        MaintenanceResult::Ok
    });
}
