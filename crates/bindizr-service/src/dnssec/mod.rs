//! DNSSEC zone signing: key management and rollover, the signed-view hook
//! every zone-data mutation runs before its serial bump, and the maintenance
//! scheduler. Whether a zone is signed is carried by its key rows, the
//! parameters it signs under by the policy `zones.dnssec_policy_id` names;
//! every transition journals its delta so secondaries follow via IXFR.
//!
//! Rollover is RFC 7583 pre-publish: `published` ahead of use, `active` once
//! caches know the key (automatic for ZSKs, `ds-seen` for CSK/KSK), `retired`
//! until caches drain, then removed.

mod keys;
mod lifecycle;
mod maintenance;
mod rollover;
mod status;

use bindizr_core::dns::dnssec::SignedViewParams;
use chrono::{Duration, Utc};
pub use maintenance::init_maintenance_scheduler;

use crate::{
    database::repository::LockLevel,
    error::ServiceError,
    log_warn,
    model::{
        dnssec_key::DnssecKey,
        dnssec_policy::DnssecPolicy,
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::{RepositoryService, RepositoryTx},
    zone::ZoneService,
};

/// Window the per-RRset expirations spread over, so one re-signing pass does
/// not come due for every RRset at once. Small next to the refresh window.
const MAX_EXPIRATION_JITTER_SECS: u64 = 21_600;

/// Backdated inception absorbs validator clock skew; one hour covers any
/// sane offset.
const SIGNATURE_INCEPTION_OFFSET_SECS: i64 = 3600;

/// Enables, disables, rolls, and reports DNSSEC signing for zones.
pub struct DnssecService;

impl DnssecService {
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
        let policy = Self::get_zone_policy_tx(tx, zone).await?;
        Self::sign_zone_locked(tx, zone, &policy, new_serial, &keys, false).await?;
        Ok(())
    }

    /// Re-sign the locked zone under a freshly advanced serial, riding the
    /// same serial/IXFR mechanics as any record change; `None` (serial kept)
    /// when nothing needed replacing.
    async fn resign_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        policy: &DnssecPolicy,
        keys: &[DnssecKey],
        force: bool,
    ) -> Result<Option<i32>, ServiceError> {
        let new_serial = crate::serial::generate_serial(Some(zone.serial))?;
        if !Self::sign_zone_locked(tx, zone, policy, new_serial, keys, force).await? {
            return Ok(None);
        }
        ZoneService::advance_serial_tx(tx, zone, new_serial).await?;
        Ok(Some(new_serial))
    }

    /// The policy the zone signs under, or `None` for an unsigned zone. Read
    /// unlocked: a policy in use cannot be deleted (FK), and its editable
    /// fields are safe to read at any moment.
    pub(crate) async fn find_zone_policy_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
    ) -> Result<Option<DnssecPolicy>, ServiceError> {
        let Some(policy_id) = zone.dnssec_policy_id else {
            return Ok(None);
        };
        RepositoryService::get_dnssec_policy_tx(tx, policy_id, LockLevel::None)
            .await?
            .map(Some)
            .ok_or_else(|| {
                ServiceError::internal(format!(
                    "zone {} references a missing DNSSEC policy",
                    zone.name.as_str()
                ))
            })
    }

    /// The policy a signed zone signs under; a signed zone without one is a
    /// broken invariant, never a caller error.
    pub(crate) async fn get_zone_policy_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
    ) -> Result<DnssecPolicy, ServiceError> {
        Self::find_zone_policy_tx(tx, zone).await?.ok_or_else(|| {
            ServiceError::internal(format!(
                "zone {} is signed but has no DNSSEC policy",
                zone.name.as_str()
            ))
        })
    }

    /// Load the zone (locked at `lock_level`) together with its policy and
    /// signing keys; a zone with no keys reads as not DNSSEC-enabled.
    pub(crate) async fn get_signed_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone_name: &str,
        lock_level: LockLevel,
    ) -> Result<(Zone, DnssecPolicy, Vec<DnssecKey>), ServiceError> {
        let zone = ZoneService::get_by_name_tx(tx, zone_name, lock_level).await?;
        let keys = RepositoryService::list_dnssec_keys_tx(tx, zone.id, LockLevel::None).await?;
        if keys.is_empty() {
            return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
        }
        let policy = Self::get_zone_policy_tx(tx, &zone).await?;
        Ok((zone, policy, keys))
    }

    /// The scheduler's form of [`Self::get_signed_zone_tx`]: `None` when the
    /// zone was deleted or unsigned since its id was listed.
    pub(crate) async fn find_signed_zone_by_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<(Zone, DnssecPolicy, Vec<DnssecKey>)>, ServiceError> {
        let Some(zone) = RepositoryService::get_zone_tx(tx, zone_id, lock_level).await? else {
            return Ok(None);
        };
        let keys = RepositoryService::list_dnssec_keys_tx(tx, zone.id, LockLevel::None).await?;
        if keys.is_empty() {
            return Ok(None);
        }
        let policy = Self::get_zone_policy_tx(tx, &zone).await?;
        Ok(Some((zone, policy, keys)))
    }

    /// Returns whether anything changed; with `force`, stored signatures are
    /// ignored instead of reused.
    async fn sign_zone_locked(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        policy: &DnssecPolicy,
        new_serial: i32,
        keys: &[DnssecKey],
        force: bool,
    ) -> Result<bool, ServiceError> {
        let records = RepositoryService::list_records_tx(tx, zone.id, LockLevel::None).await?;
        let prev = RepositoryService::list_dnssec_records_tx(tx, zone.id, LockLevel::None).await?;
        let withdraw_parent_ds = RepositoryService::get_dnssec_withdrawal_tx(tx, zone.id)
            .await?
            .is_some();

        let now = Utc::now();
        let diff = SignedViewParams {
            zone,
            new_serial,
            records: &records,
            keys,
            prev: &prev,
            denial: policy.denial,
            now,
            inception: now - Duration::seconds(SIGNATURE_INCEPTION_OFFSET_SECS),
            expiration: now + Duration::days(i64::from(policy.signature_validity_days)),
            expiration_jitter_secs: MAX_EXPIRATION_JITTER_SECS as i64,
            refresh_secs: i64::from(policy.signature_refresh_days) * 86_400,
            force,
            withdraw_parent_ds,
        }
        .compute()
        .map_err(ServiceError::dnssec_signing_failed)?;

        if diff.is_empty() {
            return Ok(false);
        }

        // Caches can hold what this pass serves for these TTLs; retirement
        // reads the running maximum back when stamping its removal deadline.
        let data_ttl = records
            .iter()
            .map(|record| record.ttl)
            .chain([zone.default_ttl, zone.minimum_ttl])
            .max()
            .unwrap_or(zone.default_ttl);
        for key in keys {
            let signed_ttl = if key.signs_zone_data(keys) {
                data_ttl
            } else if key.signs_key_rrsets() {
                zone.default_ttl
            } else {
                continue;
            };
            if signed_ttl > key.max_signed_ttl {
                RepositoryService::update_dnssec_key_max_signed_ttl_tx(tx, key.id, signed_ttl)
                    .await?;
            }
        }

        // DELs before ADDs; derived rows journal their wire RDATA, not a value.
        let mut changes = Vec::with_capacity(diff.removed.len() + diff.added.len());
        for row in &diff.removed {
            changes.push(ZoneChange {
                zone_id: zone.id,
                serial: new_serial,
                operation: ChangeOperation::Del,
                record_name: row.name.clone(),
                record_type: JournalRecordType::Derived(row.record_type),
                record_value: None,
                record_rdata: Some(row.rdata.clone()),
                record_ttl: row.ttl,
                record_priority: None,
                derived: true,
            });
        }
        for row in &diff.added {
            changes.push(ZoneChange {
                zone_id: zone.id,
                serial: new_serial,
                operation: ChangeOperation::Add,
                record_name: row.name.clone(),
                record_type: JournalRecordType::Derived(row.record_type),
                record_value: None,
                record_rdata: Some(row.rdata.clone()),
                record_ttl: row.ttl,
                record_priority: None,
                derived: true,
            });
        }
        RepositoryService::create_zone_journal_tx(tx, &changes).await?;
        let removed_ids: Vec<i32> = diff.removed.iter().map(|row| row.id).collect();
        RepositoryService::delete_dnssec_records_tx(tx, &removed_ids).await?;
        RepositoryService::create_dnssec_records_tx(tx, &diff.added).await?;
        Ok(true)
    }
}

fn key_layout(split_keys: bool) -> &'static str {
    if split_keys {
        "split KSK/ZSK keys"
    } else {
        "a single CSK"
    }
}

async fn notify_zone(zone_name: &str) {
    if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name)).await {
        log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
    }
}
