//! The periodic maintenance task: journal retention, signature refresh, and
//! the rollover steps that advance on deadlines rather than operator action.

use std::sync::OnceLock;

use bindizr_core::{config::bindizr_config, metrics::metrics};
use chrono::{DateTime, Duration, Utc};

use super::{DnssecService, notify_zone};
use crate::{
    database::repository::LockLevel,
    error::ServiceError,
    log_error, log_info,
    model::dnssec_key::{DnssecKeyRole, DnssecKeyState},
    repository::RepositoryService,
    serial::generate_serial,
    zone::ZoneService,
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
            run_maintenance_pass().await;
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

    let refresh_cutoff =
        Utc::now() + Duration::days(i64::from(config.dnssec.signature_refresh_days));
    match RepositoryService::list_rrsig_zone_ids_expiring_before(refresh_cutoff).await {
        Ok(zone_ids) => {
            for zone_id in zone_ids {
                match sign_zone_by_id(zone_id).await {
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

    // ZSK rollover needs no parent interaction, so a configured lifetime lets
    // the scheduler start it too; CSK rollover stays the operator's.
    let zsk_lifetime_days = config.dnssec.zsk_lifetime_days;
    if zsk_lifetime_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(zsk_lifetime_days));
        match RepositoryService::list_dnssec_key_zone_ids_by_role_and_state_older_than(
            DnssecKeyRole::Zsk,
            DnssecKeyState::Active,
            cutoff,
        )
        .await
        {
            Ok(zone_ids) => {
                for zone_id in zone_ids {
                    match start_zsk_rollover_by_zone_id(zone_id, cutoff).await {
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
    }

    // ZSK promotion needs no parent interaction, so it advances on its own
    // once the deadline stamped at publication has passed.
    match RepositoryService::list_dnssec_keys_by_state_eligible_before(
        DnssecKeyState::Published,
        Utc::now(),
    )
    .await
    {
        Ok(keys) => {
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

/// Prune journal and version rows older than `cutoff` in one transaction: a
/// serial pruned from one table but not the other would read to IXFR clients
/// as a journal gap or a missing SOA. Returns (journal, version) rows deleted.
async fn prune_zone_history(cutoff: DateTime<Utc>) -> Result<(u64, u64), ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to prune zone history").await?;
    let result = async {
        let journal_rows =
            RepositoryService::prune_zone_journal_older_than_tx(&mut tx, cutoff).await?;
        let version_rows =
            RepositoryService::prune_zone_versions_older_than_tx(&mut tx, cutoff).await?;
        Ok::<_, ServiceError>((journal_rows, version_rows))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to prune zone history").await
}

/// Re-sign one zone in its own transaction, bumping the serial only when the
/// pass actually replaced signatures. `None` when there was nothing to do
/// (zone deleted or unsigned meanwhile, or a concurrent mutation re-signed it).
async fn sign_zone_by_id(zone_id: i32) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to sign zone").await?;
    let result = async {
        let Some(zone) =
            RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };
        let keys =
            RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
        if keys.is_empty() {
            return Ok(None);
        }

        let new_serial = generate_serial(Some(zone.serial))?;
        if !DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await? {
            return Ok(None);
        }
        ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to sign zone").await
}

/// Pre-publish a replacement for a zone's lifetime-expired ZSK in its own
/// transaction. `None` when the state moved on concurrently.
async fn start_zsk_rollover_by_zone_id(
    zone_id: i32,
    cutoff: DateTime<Utc>,
) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to start key rollover").await?;
    let result = async {
        let Some(zone) =
            RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };
        let keys =
            RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
        if keys.is_empty() || keys.iter().any(|key| key.state != DnssecKeyState::Active) {
            return Ok(None);
        }
        let Some(template) = keys
            .iter()
            .find(|key| key.role == DnssecKeyRole::Zsk && key.created_at < cutoff)
        else {
            return Ok(None);
        };

        let new_key = DnssecService::publish_replacement_key_tx(&mut tx, &zone, template).await?;
        let mut keys = keys;
        keys.push(new_key);
        let new_serial = generate_serial(Some(zone.serial))?;
        DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
        ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to start key rollover").await
}

/// Promote a zone's hold-down-expired pre-published ZSKs in its own
/// transaction. `None` when the state moved on concurrently.
async fn promote_zsks_by_zone_id(zone_id: i32) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
    let result = async {
        let Some(zone) =
            RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };
        let keys =
            RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

        let now = Utc::now();
        let due: Vec<i32> = keys
            .iter()
            .filter(|key| {
                key.role == DnssecKeyRole::Zsk
                    && key.state == DnssecKeyState::Published
                    && key.eligible_at <= now
            })
            .map(|key| key.id)
            .collect();
        if due.is_empty() {
            return Ok(None);
        }

        let keys = DnssecService::promote_published_keys_tx(&mut tx, &zone, keys, &due).await?;

        let new_serial = generate_serial(Some(zone.serial))?;
        DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
        ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await
}

/// Remove a zone's hold-down-expired retired keys in its own transaction.
async fn remove_retired_keys_by_zone_id(zone_id: i32) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to remove retired keys").await?;
    let result = async {
        let Some(zone) =
            RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };
        let keys =
            RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

        let now = Utc::now();
        let mut remaining = Vec::with_capacity(keys.len());
        let mut removed = 0usize;
        for key in keys {
            if key.state == DnssecKeyState::Retired && key.eligible_at <= now {
                RepositoryService::delete_dnssec_key_tx(&mut tx, key.id).await?;
                removed += 1;
            } else {
                remaining.push(key);
            }
        }
        if removed == 0 || remaining.is_empty() {
            return Ok(None);
        }

        let new_serial = generate_serial(Some(zone.serial))?;
        DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &remaining, false).await?;
        ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to remove retired keys").await
}
