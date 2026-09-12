//! The periodic maintenance task: journal retention, signature refresh, and
//! the rollover steps that advance on deadlines rather than operator action.

mod steps;

use std::sync::OnceLock;

use bindizr_core::{config::bindizr_config, metrics::metrics};
use chrono::{Duration, Utc};

use self::steps::{
    promote_zsks_by_zone_id, prune_zone_history, remove_retired_keys_by_zone_id,
    sign_zone_by_zone_id, start_zsk_rollover_by_zone_id,
};
use super::notify_zone;
use crate::{
    log_error, log_info,
    model::dnssec_key::{DnssecKeyRole, DnssecKeyState},
    repository::RepositoryService,
};

/// Scheduler tick; plenty next to the day-scale windows it enforces.
const MAINTENANCE_INTERVAL_SECS: u64 = 3600;

static MAINTENANCE_SCHEDULER: OnceLock<()> = OnceLock::new();

/// Start the periodic maintenance task. Called once from the daemon after
/// the database is initialized; later calls are no-ops.
pub fn init_maintenance_scheduler() {
    if MAINTENANCE_SCHEDULER.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            // A panic in the pass would otherwise unwind the scheduler itself.
            if let Err(e) = tokio::spawn(run_maintenance_pass()).await {
                log_error!("DNSSEC maintenance pass did not finish: {}", e);
                metrics()
                    .dnssec_maintenance_runs_total
                    .with_label_values(&["panic"])
                    .inc();
            }
        }
    });
}

/// One scheduler pass: journal retention, signature refresh, and rollover
/// advancement. Failures are logged, never fatal.
async fn run_maintenance_pass() {
    let config = bindizr_config();
    let mut failed = false;

    let retention_days = config.dns.journal_retention_days;
    if retention_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
        match prune_zone_history(cutoff).await {
            Ok((journal_rows, version_rows)) if journal_rows > 0 || version_rows > 0 => {
                log_info!(
                    "Pruned {} journal and {} version rows",
                    journal_rows,
                    version_rows
                )
            }
            Ok(_) => {}
            Err(e) => {
                failed = true;
                log_error!("Zone history pruning failed: {}", e)
            }
        }
    }

    match RepositoryService::list_rrsig_zone_ids_expiring_within_refresh(Utc::now()).await {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match sign_zone_by_zone_id(zone_id).await {
                    Ok(Some(zone_name)) => {
                        log_info!("Re-signed zone {} ahead of signature expiry", zone_name);
                        notify_zone(&zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log_error!("Re-signing zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log_error!("Re-signing scan failed: {}", e)
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
                        log_info!("Started scheduled ZSK rollover for zone {}", zone_name);
                        notify_zone(&zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log_error!(
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
            log_error!("ZSK lifetime scan failed: {}", e)
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
                        log_info!("Promoted pre-published ZSK for zone {}", zone_name);
                        notify_zone(&zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log_error!("ZSK promotion for zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log_error!("Rollover promotion scan failed: {}", e)
        }
    }

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
                        log_info!("Removed retired DNSSEC key(s) for zone {}", zone_name);
                        notify_zone(&zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        failed = true;
                        log_error!("Retired-key removal for zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => {
            failed = true;
            log_error!("Retired-key scan failed: {}", e)
        }
    }

    metrics()
        .dnssec_maintenance_runs_total
        .with_label_values(&[if failed { "error" } else { "ok" }])
        .inc();
}
