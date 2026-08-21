//! DNSSEC zone signing: key management and rollover, the signed-view hook
//! every zone-data mutation runs before its serial bump, and the maintenance
//! scheduler. Whether a zone is signed is carried by its key rows; every
//! transition journals its delta so secondaries follow via IXFR.
//!
//! Rollover is RFC 7583 pre-publish: `published` ahead of use, `active` once
//! caches know the key (automatic for ZSKs, `ds-seen` for CSK/KSK), `retired`
//! until caches drain, then removed.

mod signed_view;
#[cfg(test)]
mod tests;

use std::sync::OnceLock;

use base64::Engine;
use bindizr_core::config::bindizr_config;
use chrono::{DateTime, Duration, Utc};
use rand::RngExt;

use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    log_error, log_info, log_warn,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_record::DnssecRecord,
        zone::{DnssecDenial, Zone},
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::{RepositoryService, RepositoryTx},
    serial::generate_serial,
    types::{DnssecDsInfo, DnssecKeyInfo, GetDnssecStatusResponse},
    zone::ZoneService,
};

/// Spread signature expirations so one zone's signatures do not all come due
/// in the same re-signing pass. Small next to the refresh window (days).
const MAX_EXPIRATION_JITTER_SECS: u64 = 21_600;

/// Backdated inception absorbs validator clock skew; one hour covers any
/// sane offset.
const SIGNATURE_INCEPTION_OFFSET_SECS: i64 = 3600;

/// Scheduler tick; plenty next to the day-scale windows it enforces.
const MAINTENANCE_INTERVAL_SECS: u64 = 3600;

static MAINTENANCE_SCHEDULER: OnceLock<()> = OnceLock::new();

/// Enables, disables, rolls, and reports DNSSEC signing for zones.
pub struct DnssecService;

impl DnssecService {
    /// Enable DNSSEC for a zone: generate its key(s) and sign the whole zone.
    pub async fn enable(
        caller: &Caller,
        zone_name: &str,
        algorithm: Option<&str>,
        denial: Option<&str>,
        split_keys: bool,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        let algorithm = match algorithm {
            Some(name) => name
                .parse::<DnssecAlgorithm>()
                .map_err(ServiceError::invalid_input)?,
            None => DnssecAlgorithm::EcdsaP256Sha256,
        };
        let denial = match denial {
            Some(name) => name
                .parse::<DnssecDenial>()
                .map_err(ServiceError::invalid_input)?,
            None => DnssecDenial::Nsec,
        };

        let mut tx = RepositoryService::begin_tx("failed to enable DNSSEC").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let existing =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if !existing.is_empty() {
                return Err(ServiceError::dnssec_already_enabled(zone.name.as_str()));
            }

            let now = Utc::now();
            RepositoryService::update_zone_dnssec_denial_tx(&mut tx, zone.id, denial).await?;
            let zone = Zone {
                dnssec_denial: denial,
                ..zone
            };

            let roles: &[DnssecKeyRole] = if split_keys {
                &[DnssecKeyRole::Ksk, DnssecKeyRole::Zsk]
            } else {
                &[DnssecKeyRole::Csk]
            };
            let mut keys = Vec::with_capacity(roles.len());
            for role in roles {
                let key = generate_key(&zone, algorithm, *role, DnssecKeyState::Active, now)?;
                keys.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);
            }

            // Signing changes the zone content secondaries hold, so it rides the
            // same serial/IXFR mechanics as any record change.
            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = earliest_expiry_tx(&mut tx, zone.id).await?;
            build_status(&zone, denial, &keys, earliest, new_serial)
        }
        .await;
        let response = RepositoryService::finish_tx(tx, result, "failed to enable DNSSEC").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Disable DNSSEC for a zone. `confirm_insecure` acknowledges the
    /// going-insecure procedure ([`crate::types::DisableDnssecRequest`]).
    pub async fn disable(
        caller: &Caller,
        zone_name: &str,
        confirm_insecure: bool,
    ) -> Result<(), ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        if !confirm_insecure {
            return Err(ServiceError::invalid_input(
                "disabling DNSSEC makes the zone bogus for validating resolvers while the parent \
                 still publishes a DS record; remove the DS, wait out its TTL, then retry with \
                 confirm_insecure set",
            ));
        }

        let mut tx = RepositoryService::begin_tx("failed to disable DNSSEC").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if keys.is_empty() {
                return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
            }

            let derived =
                RepositoryService::list_dnssec_records_tx(&mut tx, zone.id, LockLevel::None)
                    .await?;

            let new_serial = generate_serial(Some(zone.serial))?;
            let changes = derived_changes(zone.id, new_serial, &derived, &[])?;
            RepositoryService::create_zone_journal_tx(&mut tx, &changes).await?;
            RepositoryService::delete_dnssec_records_by_zone_id_tx(&mut tx, zone.id).await?;
            RepositoryService::delete_dnssec_keys_by_zone_id_tx(&mut tx, zone.id).await?;
            RepositoryService::update_zone_dnssec_denial_tx(&mut tx, zone.id, DnssecDenial::Nsec)
                .await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            Ok(zone.name.as_str().to_string())
        }
        .await;
        let zone_name =
            RepositoryService::finish_tx(tx, result, "failed to disable DNSSEC").await?;

        notify_zone(&zone_name).await;
        Ok(())
    }

    /// DNSSEC signing state of a zone; `enabled: false` with empty key and DS
    /// lists for an unsigned zone.
    pub async fn get_status(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let zone = ZoneService::lookup_by_name(zone_name).await?;
        let keys = RepositoryService::list_dnssec_keys(zone.id).await?;
        let derived = RepositoryService::list_dnssec_records(zone.id).await?;
        let earliest = derived.iter().filter_map(|row| row.expires_at).min();

        build_status(&zone, zone.dnssec_denial, &keys, earliest, zone.serial)
    }

    /// Re-sign a zone from scratch, discarding stored signatures (recovery
    /// hatch when stored state is doubted).
    pub async fn sign(caller: &Caller, zone_name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to sign zone").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if keys.is_empty() {
                return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
            }
            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, true).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
            Ok(zone.name.as_str().to_string())
        }
        .await;
        let zone_name = RepositoryService::finish_tx(tx, result, "failed to sign zone").await?;

        notify_zone(&zone_name).await;
        Ok(())
    }

    /// Start a key rollover: pre-publish a replacement that signs no zone
    /// data until [`Self::rollover_ds_seen`].
    pub async fn rollover_start(
        caller: &Caller,
        zone_name: &str,
        role: Option<&str>,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to start key rollover").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if keys.is_empty() {
                return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
            }
            if keys.iter().any(|key| key.state != DnssecKeyState::Active) {
                return Err(ServiceError::dnssec_rollover_in_progress(
                    zone.name.as_str(),
                ));
            }

            let target_role = match role {
                Some(name) => {
                    let parsed = name
                        .parse::<DnssecKeyRole>()
                        .map_err(ServiceError::invalid_input)?;
                    if !keys.iter().any(|key| key.role == parsed) {
                        return Err(ServiceError::invalid_input(format!(
                            "zone '{}' has no {} key to roll",
                            zone.name, parsed
                        )));
                    }
                    parsed
                }
                None => {
                    if keys.iter().all(|key| key.role == DnssecKeyRole::Csk) {
                        DnssecKeyRole::Csk
                    } else {
                        return Err(ServiceError::invalid_input(
                            "this zone uses split keys; pass the role to roll (ksk or zsk)",
                        ));
                    }
                }
            };

            // The replacement keeps the algorithm: an algorithm change is a
            // different, stricter procedure (RFC 6840, Section 5.11) and is not
            // supported.
            let template = keys
                .iter()
                .find(|key| key.role == target_role)
                .expect("validated above that the role exists");
            let now = Utc::now();
            let new_key = generate_key(
                &zone,
                template.algorithm,
                target_role,
                DnssecKeyState::Published,
                now,
            )?;
            let new_key = RepositoryService::create_dnssec_key_tx(&mut tx, new_key).await?;

            let mut keys = keys;
            keys.push(new_key);
            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = earliest_expiry_tx(&mut tx, zone.id).await?;
            build_status(&zone, zone.dnssec_denial, &keys, earliest, new_serial)
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to start key rollover").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// The operator's confirmation that the new DS is at the parent and its
    /// TTL has passed: promotes the pre-published key(s) and retires the keys
    /// they replace. ZSK rollovers are promoted by the scheduler instead.
    pub async fn rollover_ds_seen(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if keys.is_empty() {
                return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
            }

            if !keys
                .iter()
                .any(|key| key.state == DnssecKeyState::Published)
            {
                return Err(ServiceError::dnssec_no_rollover_in_progress(
                    zone.name.as_str(),
                ));
            }
            // ZSKs have no parent DS to confirm; the scheduler promotes them
            // after the publish hold-down.
            let ds_published: Vec<i32> = keys
                .iter()
                .filter(|key| {
                    key.state == DnssecKeyState::Published && key.role != DnssecKeyRole::Zsk
                })
                .map(|key| key.id)
                .collect();
            if ds_published.is_empty() {
                return Err(ServiceError::invalid_input(
                    "this rollover replaces the ZSK, which involves no parent DS; it is \
                     promoted automatically after the publish hold-down",
                ));
            }
            let Some(keys) =
                promote_published_keys_tx(&mut tx, &zone, keys, Some(&ds_published)).await?
            else {
                return Err(ServiceError::dnssec_no_rollover_in_progress(
                    zone.name.as_str(),
                ));
            };

            let new_serial = generate_serial(Some(zone.serial))?;
            DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = earliest_expiry_tx(&mut tx, zone.id).await?;
            build_status(&zone, zone.dnssec_denial, &keys, earliest, new_serial)
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Derived records of a zone's signed view, for assembling transfers.
    /// Takes no caller: DNS-plane reads are authorized by the transfer ACL.
    pub async fn list_records(zone_id: i32) -> Result<Vec<DnssecRecord>, ServiceError> {
        RepositoryService::list_dnssec_records(zone_id).await
    }

    /// Recompute the zone's signed view inside the caller's mutation
    /// transaction, journaling the delta under `new_serial`. No-op for an
    /// unsigned zone. The caller holds the zone row lock and calls this after
    /// its record writes, before `advance_serial_tx`.
    pub(crate) async fn sign_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        new_serial: i32,
    ) -> Result<(), ServiceError> {
        let keys = RepositoryService::list_dnssec_keys_tx(tx, zone.id, LockLevel::None).await?;
        if keys.is_empty() {
            return Ok(());
        }
        Self::sign_zone_locked(tx, zone, new_serial, &keys, false).await?;
        Ok(())
    }

    /// Returns whether anything changed; with `force`, stored signatures are
    /// ignored instead of reused.
    async fn sign_zone_locked(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        new_serial: i32,
        keys: &[DnssecKey],
        force: bool,
    ) -> Result<bool, ServiceError> {
        let records = RepositoryService::list_records_tx(tx, zone.id, LockLevel::None).await?;
        let prev = RepositoryService::list_dnssec_records_tx(tx, zone.id, LockLevel::None).await?;

        let dnssec = &bindizr_config().dnssec;
        let now = Utc::now();
        let jitter = rand::rng().random_range(0..=MAX_EXPIRATION_JITTER_SECS);
        let diff = signed_view::compute_signed_view(&signed_view::SignedViewParams {
            zone,
            new_serial,
            records: &records,
            keys,
            prev: &prev,
            denial: zone.dnssec_denial,
            now,
            inception: now - Duration::seconds(SIGNATURE_INCEPTION_OFFSET_SECS),
            expiration: now + Duration::days(i64::from(dnssec.signature_validity_days))
                - Duration::seconds(jitter as i64),
            refresh_secs: i64::from(dnssec.signature_refresh_days) * 86_400,
            force,
        })?;

        if diff.is_empty() {
            return Ok(false);
        }

        let changes = derived_changes(zone.id, new_serial, &diff.removed, &diff.added)?;
        RepositoryService::create_zone_journal_tx(tx, &changes).await?;
        let removed_ids: Vec<i32> = diff.removed.iter().map(|row| row.id).collect();
        RepositoryService::delete_dnssec_records_tx(tx, &removed_ids).await?;
        RepositoryService::create_dnssec_records_tx(tx, &diff.added).await?;
        Ok(true)
    }
}

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

    let retention_days = config.dns.journal_retention_days;
    if retention_days > 0 {
        let cutoff = Utc::now() - Duration::days(i64::from(retention_days));
        match RepositoryService::prune_zone_journal_older_than(cutoff).await {
            Ok(rows) if rows > 0 => log_info!("Pruned {} journal rows", rows),
            Ok(_) => {}
            Err(e) => log_error!("Journal pruning failed: {}", e),
        }
        match RepositoryService::prune_zone_versions_older_than(cutoff).await {
            Ok(rows) if rows > 0 => log_info!("Pruned {} version rows", rows),
            Ok(_) => {}
            Err(e) => log_error!("Version pruning failed: {}", e),
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
                    Err(e) => log_error!("Re-signing zone id {} failed: {}", zone_id, e),
                }
            }
        }
        Err(e) => log_error!("Re-signing scan failed: {}", e),
    }

    // ZSK promotion needs no parent interaction, so it advances on its own
    // once caches have had the publish hold-down to learn the new DNSKEY.
    let publish_cutoff =
        Utc::now() - Duration::seconds(config.dnssec.rollover_publish_holddown_secs as i64);
    match RepositoryService::list_dnssec_keys_by_state_entered_before(
        DnssecKeyState::Published,
        publish_cutoff,
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
                match promote_zsks_for_zone(zone_id, publish_cutoff).await {
                    Ok(Some(zone_name)) => {
                        log_info!("Promoted pre-published ZSK for zone {}", zone_name);
                        notify_zone(&zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => log_error!("ZSK promotion for zone id {} failed: {}", zone_id, e),
                }
            }
        }
        Err(e) => log_error!("Rollover promotion scan failed: {}", e),
    }

    let retire_cutoff =
        Utc::now() - Duration::seconds(config.dnssec.rollover_retire_holddown_secs as i64);
    match RepositoryService::list_dnssec_keys_by_state_entered_before(
        DnssecKeyState::Retired,
        retire_cutoff,
    )
    .await
    {
        Ok(keys) => {
            let mut zone_ids: Vec<i32> = keys.iter().map(|key| key.zone_id).collect();
            zone_ids.dedup();
            for zone_id in zone_ids {
                match remove_retired_keys_for_zone(zone_id, retire_cutoff).await {
                    Ok(Some(zone_name)) => {
                        log_info!("Removed retired DNSSEC key(s) for zone {}", zone_name);
                        notify_zone(&zone_name).await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log_error!("Retired-key removal for zone id {} failed: {}", zone_id, e)
                    }
                }
            }
        }
        Err(e) => log_error!("Retired-key scan failed: {}", e),
    }
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

/// Promote a zone's hold-down-expired pre-published ZSKs in its own
/// transaction. `None` when the state moved on concurrently.
async fn promote_zsks_for_zone(
    zone_id: i32,
    cutoff: DateTime<Utc>,
) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
    let result = async {
        let Some(zone) =
            RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };
        let keys =
            RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

        // The effective hold-down is at least the DNSKEY TTL, so resolvers
        // age out the pre-rollover RRset first (RFC 7583, Section 3.3.1).
        let cutoff = cutoff.min(Utc::now() - Duration::seconds(zone.default_ttl as i64));
        let due: Vec<i32> = keys
            .iter()
            .filter(|key| {
                key.role == DnssecKeyRole::Zsk
                    && key.state == DnssecKeyState::Published
                    && key.state_changed_at < cutoff
            })
            .map(|key| key.id)
            .collect();
        if due.is_empty() {
            return Ok(None);
        }

        let Some(keys) = promote_published_keys_tx(&mut tx, &zone, keys, Some(&due)).await? else {
            return Ok(None);
        };

        let new_serial = generate_serial(Some(zone.serial))?;
        DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
        ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await
}

/// Remove a zone's hold-down-expired retired keys in its own transaction.
async fn remove_retired_keys_for_zone(
    zone_id: i32,
    cutoff: DateTime<Utc>,
) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to remove retired keys").await?;
    let result = async {
        let Some(zone) =
            RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };
        let keys =
            RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

        let mut remaining = Vec::with_capacity(keys.len());
        let mut removed = 0usize;
        for key in keys {
            if key.state == DnssecKeyState::Retired && key.state_changed_at < cutoff {
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

/// Promote published keys (all, or just `only`) and retire the active keys
/// of the same roles; `None` when nothing was promoted.
async fn promote_published_keys_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    keys: Vec<DnssecKey>,
    only: Option<&[i32]>,
) -> Result<Option<Vec<DnssecKey>>, ServiceError> {
    let now = Utc::now();
    let promoted_ids: Vec<i32> = keys
        .iter()
        .filter(|key| {
            key.state == DnssecKeyState::Published && only.is_none_or(|ids| ids.contains(&key.id))
        })
        .map(|key| key.id)
        .collect();
    if promoted_ids.is_empty() {
        return Ok(None);
    }
    let promoted_roles: Vec<DnssecKeyRole> = keys
        .iter()
        .filter(|key| promoted_ids.contains(&key.id))
        .map(|key| key.role)
        .collect();

    let mut updated = Vec::with_capacity(keys.len());
    for mut key in keys {
        if promoted_ids.contains(&key.id) {
            RepositoryService::update_dnssec_key_state_tx(tx, key.id, DnssecKeyState::Active, now)
                .await?;
            key.state = DnssecKeyState::Active;
            key.state_changed_at = now;
        } else if key.state == DnssecKeyState::Active && promoted_roles.contains(&key.role) {
            RepositoryService::update_dnssec_key_state_tx(tx, key.id, DnssecKeyState::Retired, now)
                .await?;
            key.state = DnssecKeyState::Retired;
            key.state_changed_at = now;
        }
        updated.push(key);
    }

    log_info!(
        "Promoted {} pre-published DNSSEC key(s) for zone {}",
        promoted_ids.len(),
        zone.name
    );
    Ok(Some(updated))
}

fn generate_key(
    zone: &Zone,
    algorithm: DnssecAlgorithm,
    role: DnssecKeyRole,
    state: DnssecKeyState,
    now: DateTime<Utc>,
) -> Result<DnssecKey, ServiceError> {
    let params = match algorithm {
        DnssecAlgorithm::EcdsaP256Sha256 => domain::crypto::sign::GenerateParams::EcdsaP256Sha256,
        DnssecAlgorithm::Ed25519 => domain::crypto::sign::GenerateParams::Ed25519,
    };
    let (secret, dnskey) = domain::crypto::sign::generate(&params, role.flags())
        .map_err(|e| ServiceError::internal(format!("failed to generate DNSSEC key: {}", e)))?;

    Ok(DnssecKey {
        id: 0,
        zone_id: zone.id,
        role,
        algorithm,
        key_tag: i32::from(dnskey.key_tag()),
        public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
        private_key: secret.display_as_bind().to_string(),
        state,
        state_changed_at: now,
        created_at: now,
    })
}

/// Journal rows for a derived-plane delta: DELs for `removed`, ADDs for
/// `added`, all flagged `derived` with wire-rdata encoded values.
fn derived_changes(
    zone_id: i32,
    new_serial: i32,
    removed: &[DnssecRecord],
    added: &[DnssecRecord],
) -> Result<Vec<ZoneChange>, ServiceError> {
    let change =
        |operation: ChangeOperation, row: &DnssecRecord| -> Result<ZoneChange, ServiceError> {
            Ok(ZoneChange {
                zone_id,
                serial: new_serial,
                operation,
                record_name: row.name.clone(),
                record_type: JournalRecordType::Derived(row.record_type),
                record_value: row.rdata.to_journal_value(),
                record_ttl: row.ttl,
                record_priority: None,
                derived: true,
            })
        };

    let mut changes = Vec::with_capacity(removed.len() + added.len());
    for row in removed {
        changes.push(change(ChangeOperation::Del, row)?);
    }
    for row in added {
        changes.push(change(ChangeOperation::Add, row)?);
    }
    Ok(changes)
}

fn build_status(
    zone: &Zone,
    denial: DnssecDenial,
    keys: &[DnssecKey],
    earliest_signature_expires_at: Option<DateTime<Utc>>,
    serial: i32,
) -> Result<GetDnssecStatusResponse, ServiceError> {
    // The parent needs DS records only for the SEP keys the zone still wants
    // delegated trust for.
    let ds_records = keys
        .iter()
        .filter(|key| key.wants_parent_ds())
        .map(|key| ds_info(zone, key))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GetDnssecStatusResponse {
        zone_name: zone.name.as_str().to_string(),
        enabled: !keys.is_empty(),
        denial: denial.to_string(),
        keys: keys
            .iter()
            .map(|key| DnssecKeyInfo {
                id: key.id,
                role: key.role.to_string(),
                state: key.state.to_string(),
                state_changed_at: key.state_changed_at,
                algorithm: key.algorithm.to_string(),
                key_tag: key.key_tag,
                dnskey: format!(
                    "{} 3 {} {}",
                    key.role.flags(),
                    key.algorithm.to_int(),
                    key.public_key
                ),
                created_at: key.created_at,
            })
            .collect(),
        ds_records,
        earliest_signature_expires_at,
        serial,
    })
}

/// The key's DS form, decoded from the same RDATA the CDS records carry.
fn ds_info(zone: &Zone, key: &DnssecKey) -> Result<DnssecDsInfo, ServiceError> {
    let apex = signed_view::to_wire_name(zone.name.to_wire())
        .map_err(|e| ServiceError::internal(format!("invalid zone apex: {}", e)))?;
    let rdata = signed_view::ds_rdata_for(key, &apex)?;
    let digest = hex::encode_upper(&rdata.as_bytes()[4..]);

    Ok(DnssecDsInfo {
        key_tag: key.key_tag,
        algorithm: key.algorithm.to_int() as u8,
        digest_type: signed_view::DS_DIGEST_TYPE_SHA256,
        digest: digest.clone(),
        presentation: format!(
            "{} IN DS {} {} {} {}",
            zone.name.to_fqdn(),
            key.key_tag,
            key.algorithm.to_int(),
            signed_view::DS_DIGEST_TYPE_SHA256,
            digest
        ),
    })
}

async fn earliest_expiry_tx(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
) -> Result<Option<DateTime<Utc>>, ServiceError> {
    let derived = RepositoryService::list_dnssec_records_tx(tx, zone_id, LockLevel::None).await?;
    Ok(derived.iter().filter_map(|row| row.expires_at).min())
}

async fn notify_zone(zone_name: &str) {
    if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name)).await {
        log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
    }
}
