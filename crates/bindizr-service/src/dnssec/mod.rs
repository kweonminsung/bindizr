//! DNSSEC zone signing: key management and rollover, the signed-view hook
//! every zone-data mutation runs before its serial bump, and the scheduler.
//! Whether a zone is signed is carried by its key rows, the parameters it
//! signs under by the policy `zones.dnssec_policy_id` names;
//! every transition journals its delta so secondaries follow via IXFR.
//!
//! Promotion waits for the publish TTL and, for SEP keys, parent DS confirmation
//! by the scheduler or `ds-seen`. Retired keys remain until their cache deadlines.
//! A parent probe runs inside the transaction that acts on its answer, under
//! the zone lock, so the answer is about the keys and parent it then moves;
//! `dns.notify.timeout_secs` bounds each exchange.

mod delegation;
mod keys;
mod lifecycle;
mod parent_ns_addrs;
mod rollover;
pub mod scheduler;
mod status;
mod withdraw;

use bindizr_core::{
    dns::{
        Serial,
        dnssec::{SignedViewParams, SigningPass},
        name::ZoneName,
    },
    model::{dnssec_record::DnssecRecordId, zone::ZoneId},
};
use chrono::{Duration, Utc};
pub use delegation::check_ds;
pub(crate) use delegation::probe_delegation;
pub use keys::{export_keys, import_keys};
pub use lifecycle::{disable, enable, sign, update_settings};
pub use rollover::{advance_rollover, start_rollover};
pub(crate) use rollover::{
    promote_published_keys_tx, publish_replacement_key_tx, start_algorithm_rollover_tx,
};
pub use status::{
    count_keys_by_state, count_rrsigs_expired, count_rrsigs_expiring_within_refresh,
    count_signed_zones, get_status,
};
pub use withdraw::{cancel_withdrawal, withdraw};

use crate::{
    Context, Transaction, db,
    db::LockLevel,
    error::ServiceError,
    model::{
        dnssec_key::DnssecKey,
        dnssec_policy::DnssecPolicy,
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    zone::{self, version::ChangeSubject},
};

/// Backdated inception absorbs validator clock skew; one hour covers any
/// sane offset.
const SIGNATURE_INCEPTION_OFFSET_SECS: i64 = 3600;

/// A signed zone as its operations load it: the row, the policy it signs
/// under, and its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedZone {
    pub(crate) zone: Zone,
    pub(crate) policy: DnssecPolicy,
    pub(crate) keys: Vec<DnssecKey>,
}

/// Recompute the zone's signed view inside the caller's mutation
/// transaction, journaling the delta under `new_serial`. No-op for an
/// unsigned zone. The caller holds the zone row lock and calls this after
/// its record writes, before `advance_serial_tx`.
pub(crate) async fn sign_zone_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    new_serial: Serial,
) -> Result<(), ServiceError> {
    let keys = db::dnssec_key::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    if keys.is_empty() {
        return Ok(());
    }
    let policy = get_zone_policy_tx(tx, zone).await?;
    apply_signed_view_tx(tx, zone, &policy, new_serial, &keys, SigningPass::Refresh).await?;
    Ok(())
}

/// Re-sign the locked zone under a freshly advanced serial, riding the
/// same serial/IXFR mechanics as any record change; `None` (serial kept)
/// when nothing needed replacing.
async fn resign_zone_tx(
    cx: &Context,
    tx: &mut Transaction<'_>,
    signed: &SignedZone,
    pass: SigningPass,
    subject: &ChangeSubject,
) -> Result<Option<Serial>, ServiceError> {
    let new_serial = crate::serial::generate_serial(Some(signed.zone.serial))?;
    if !apply_signed_view_tx(
        tx,
        &signed.zone,
        &signed.policy,
        new_serial,
        &signed.keys,
        pass,
    )
    .await?
    {
        return Ok(None);
    }
    zone::advance_serial_tx(cx, tx, &signed.zone, new_serial, subject).await?;
    Ok(Some(new_serial))
}

/// The policy the zone signs under, or `None` for an unsigned zone. Read
/// unlocked: a policy in use cannot be deleted (FK), and its editable
/// fields are safe to read at any moment.
async fn find_zone_policy_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<Option<DnssecPolicy>, ServiceError> {
    let Some(policy_id) = zone.dnssec_policy_id else {
        return Ok(None);
    };
    db::dnssec_policy::get_tx(tx, policy_id, LockLevel::Unlocked)
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
async fn get_zone_policy_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<DnssecPolicy, ServiceError> {
    find_zone_policy_tx(tx, zone).await?.ok_or_else(|| {
        ServiceError::internal(format!(
            "zone {} is signed but has no DNSSEC policy",
            zone.name.as_str()
        ))
    })
}

/// Load the zone (locked at `lock_level`) together with its policy and
/// signing keys; a zone with no keys reads as not DNSSEC-enabled.
async fn get_signed_zone_tx(
    tx: &mut Transaction<'_>,
    zone_name: &ZoneName,
    lock_level: LockLevel,
) -> Result<SignedZone, ServiceError> {
    let zone = zone::get_by_name_tx(tx, zone_name, lock_level).await?;
    let keys = db::dnssec_key::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    if keys.is_empty() {
        return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
    }
    let policy = get_zone_policy_tx(tx, &zone).await?;
    Ok(SignedZone { zone, policy, keys })
}

/// The scheduler's form of [`get_signed_zone_tx`]: `None` when the
/// zone was deleted or unsigned since its id was listed.
async fn find_signed_zone_by_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    lock_level: LockLevel,
) -> Result<Option<SignedZone>, ServiceError> {
    let Some(zone) = db::zone::get_tx(tx, zone_id, lock_level).await? else {
        return Ok(None);
    };
    let keys = db::dnssec_key::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    if keys.is_empty() {
        return Ok(None);
    }
    let policy = get_zone_policy_tx(tx, &zone).await?;
    Ok(Some(SignedZone { zone, policy, keys }))
}

/// Apply the signed DNSSEC view and journal its changes under the held zone lock.
///
/// Returns whether anything changed.
async fn apply_signed_view_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    policy: &DnssecPolicy,
    new_serial: Serial,
    keys: &[DnssecKey],
    pass: SigningPass,
) -> Result<bool, ServiceError> {
    // Read both planes under the zone lock so the diff uses one consistent state.
    let records = db::record::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    let prev = db::dnssec_record::list_tx(tx, zone.id, LockLevel::Unlocked).await?;

    let withdraw_parent_ds = db::dnssec_withdrawal::get_tx(tx, zone.id).await?.is_some();

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
        expiration: now + Duration::seconds(policy.signature_validity_secs()),
        expiration_jitter_secs: policy.expiration_jitter_secs(),
        refresh_secs: policy.signature_refresh_secs(),
        pass,
        withdraw_parent_ds,
    }
    .compute()
    .map_err(ServiceError::dnssec_signing_failed)?;

    // Reused signatures and unchanged derived records need no storage writes.
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
        } else if key.signs_key_record_sets() {
            zone.default_ttl
        } else {
            continue;
        };
        if signed_ttl > key.max_signed_ttl {
            db::dnssec_key::update_max_signed_ttl_tx(tx, key.id, signed_ttl).await?;
        }
    }

    // DELs before ADDs; derived rows journal their wire RDATA, not a value.
    let mut changes = Vec::with_capacity(diff.removed.len() + diff.added.len());
    for row in &diff.removed {
        changes.push(ZoneChange {
            zone_id: zone.id,
            serial: new_serial,
            operation: ChangeOperation::Delete,
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

    // The derived rows and their IXFR journal commit in the caller's transaction.
    db::zone_change::create_many_tx(tx, &changes).await?;
    let removed_ids: Vec<DnssecRecordId> = diff.removed.iter().map(|row| row.id).collect();
    db::dnssec_record::delete_many_tx(tx, &removed_ids).await?;
    db::dnssec_record::create_many_tx(tx, &diff.added).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use bindizr_core::model::{
        dnssec_key::DnssecAlgorithm,
        dnssec_policy::{DnssecDenial, PolicyId},
    };
    use chrono::Utc;

    use super::DnssecPolicy;

    /// Build a policy fixture with the requested signature timing.
    fn policy(signature_validity_days: i32, signature_refresh_days: i32) -> DnssecPolicy {
        DnssecPolicy {
            id: PolicyId::from(1),
            name: "default".to_string(),
            algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            denial: DnssecDenial::Nsec,
            split_keys: false,
            signature_validity_days,
            signature_refresh_days,
            zsk_lifetime_days: 0,
            created_at: Utc::now(),
        }
    }

    /// Verify that jitter spreads over half the room the policy leaves.
    #[test]
    fn jitter_spreads_over_half_the_room_the_policy_leaves() {
        // The built-in default: 14 days of validity re-signed with 5 left.
        assert_eq!(
            policy(14, 5).expiration_jitter_secs(),
            (9 * 86_400) / 2,
            "a fixed window would come due for the whole zone at once"
        );
    }

    /// Verify that the earliest signature stays clear of its refresh window.
    #[test]
    fn the_earliest_signature_stays_clear_of_its_refresh_window() {
        for (validity, refresh) in [(14, 5), (30, 7), (7, 6), (2, 1)] {
            let policy = policy(validity, refresh);
            let earliest = i64::from(validity) * 86_400 - policy.expiration_jitter_secs();

            assert!(
                earliest > i64::from(refresh) * 86_400,
                "validity {validity}, refresh {refresh}: signing would land inside the window"
            );
        }
    }

    /// Verify that a policy leaving no room takes no jitter.
    #[test]
    fn a_policy_leaving_no_room_takes_no_jitter() {
        assert_eq!(policy(5, 5).expiration_jitter_secs(), 0);
        assert_eq!(policy(5, 7).expiration_jitter_secs(), 0);
    }
}
