//! Manage DNSSEC keys and rollovers; sign and journal changes before each serial bump.
//! Promotion waits for publication and SEP parent-DS confirmation; retirement waits for caches.
//! A parent probe whose answer the flow acts on (disable, ds-seen, scheduled SEP
//! promotion) holds the transaction's zone lock; the read-only `check_ds` probes
//! after its read transaction. Both are bounded by `dns.notify.timeout_secs`.

mod delegation;
mod keys;
mod lifecycle;
pub(crate) mod maintenance;
mod parent_ns_addrs;
mod rollover;
mod status;
mod withdraw;

use bindizr_core::dns::Serial;
use bindizr_core::dns::dnssec::{SignedViewDiff, SignedViewParams, SigningPass};
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::dnssec_key::DnssecKey;
use bindizr_core::model::dnssec_policy::DnssecPolicy;
use bindizr_core::model::dnssec_record::DnssecRecordId;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::{Zone, ZoneId};
use bindizr_core::model::zone_change::{ChangeOperation, JournalRecordType, ZoneChange};
use bindizr_db::LockLevel;
use chrono::{Duration, Utc};
pub use delegation::check_ds;
pub(crate) use delegation::probe_delegation;
pub use keys::{export_keys, import_keys};
pub use lifecycle::{disable, enable, sign, update_settings};
pub use rollover::{advance_rollover, start_rollover};
pub(crate) use rollover::{
    promotable_sep_key_ids, promote_published_keys_tx, publish_replacement_key_tx,
    start_algorithm_rollover_tx,
};
pub(crate) use status::lookup_status_tx;
pub use status::{
    count_keys_by_state, count_rrsigs_expired, count_rrsigs_expiring_within_refresh,
    count_signed_zones, get_status,
};
pub use withdraw::{cancel_withdrawal, withdraw};

use crate::authorization::Caller;
use crate::change::ChangeOrigin;
use crate::error::ServiceError;
use crate::{Transaction, serial, zone};

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

/// Sign and journal under `new_serial`; unsigned zones are unchanged.
/// Call with the zone locked, after record writes and before `advance_serial_tx`.
pub(crate) async fn sign_zone_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    new_serial: Serial,
) -> Result<(), ServiceError> {
    let keys = bindizr_db::dnssec_key::list_tx(tx, zone.id).await?;

    if keys.is_empty() {
        return Ok(());
    }

    let policy = lookup_zone_policy_tx(tx, zone).await?;
    apply_signed_view_tx(tx, zone, &policy, new_serial, &keys, SigningPass::Refresh).await?;

    Ok(())
}

/// Re-sign the locked zone and advance its serial/history only if signatures changed.
/// Return `None` and keep the serial when nothing needed replacing.
async fn resign_zone_tx(
    tx: &mut Transaction<'_>,
    signed: &SignedZone,
    pass: SigningPass,
    origin: &ChangeOrigin,
) -> Result<Option<Serial>, ServiceError> {
    let new_serial = serial::generate_serial(Some(signed.zone.serial));

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

    zone::advance_serial_tx(tx, &signed.zone, new_serial, origin).await?;

    Ok(Some(new_serial))
}

/// Find the signing policy unlocked, or `None` for unsigned zones.
/// The FK prevents deletion while in use; editable fields need no lock.
async fn find_zone_policy_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<Option<DnssecPolicy>, ServiceError> {
    let Some(policy_id) = zone.dnssec_policy_id else {
        return Ok(None);
    };
    bindizr_db::dnssec_policy::get_tx(tx, policy_id)
        .await?
        .map(Some)
        .ok_or_else(|| {
            ServiceError::internal(format!(
                "zone {} references a missing DNSSEC policy",
                zone.name
            ))
        })
}

/// Look up the policy a signed zone signs under; a signed zone without one
/// is a broken invariant, never a caller error.
async fn lookup_zone_policy_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
) -> Result<DnssecPolicy, ServiceError> {
    find_zone_policy_tx(tx, zone).await?.ok_or_else(|| {
        ServiceError::internal(format!(
            "zone {} is signed but has no DNSSEC policy",
            zone.name
        ))
    })
}

/// Get the zone (locked at `lock_level`), authorized for `action`, with its
/// policy and keys; a zone with no keys reads as not DNSSEC-enabled.
async fn get_signed_zone_tx(
    tx: &mut Transaction<'_>,
    caller: &Caller,
    action: Action,
    zone_name: &ZoneName,
    lock_level: LockLevel,
) -> Result<SignedZone, ServiceError> {
    let zone = zone::lookup_by_name_tx(tx, zone_name, lock_level).await?;
    caller
        .reauthenticate_tx(tx)
        .await?
        .authorize_zone_action(action, &zone)?;

    lookup_signed_zone_tx(tx, zone).await
}

/// Load the signing state of a zone already locked and authorized by the caller.
async fn lookup_signed_zone_tx(
    tx: &mut Transaction<'_>,
    zone: Zone,
) -> Result<SignedZone, ServiceError> {
    let keys = bindizr_db::dnssec_key::list_tx(tx, zone.id).await?;

    if keys.is_empty() {
        return Err(ServiceError::dnssec_not_enabled(&zone.name));
    }

    let policy = lookup_zone_policy_tx(tx, &zone).await?;

    Ok(SignedZone { zone, policy, keys })
}

/// Find a signed zone by id, the scheduler's form of [`get_signed_zone_tx`]:
/// `None` when the zone was deleted or unsigned since its id was listed.
async fn find_signed_zone_by_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    lock_level: LockLevel,
) -> Result<Option<SignedZone>, ServiceError> {
    let Some(zone) = bindizr_db::zone::get_tx(tx, zone_id, lock_level).await? else {
        return Ok(None);
    };
    let keys = bindizr_db::dnssec_key::list_tx(tx, zone.id).await?;

    if keys.is_empty() {
        return Ok(None);
    }

    let policy = lookup_zone_policy_tx(tx, &zone).await?;

    Ok(Some(SignedZone { zone, policy, keys }))
}

/// Apply and journal the signed view under the zone lock, reporting whether it changed.
async fn apply_signed_view_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    policy: &DnssecPolicy,
    new_serial: Serial,
    keys: &[DnssecKey],
    pass: SigningPass,
) -> Result<bool, ServiceError> {
    // Read both planes under the zone lock so the diff uses one consistent state.
    let records = bindizr_db::record::list_tx(tx, zone.id, LockLevel::Unlocked).await?;
    let prev = bindizr_db::dnssec_record::list_tx(tx, zone.id).await?;

    let withdraw_parent_ds = bindizr_db::dnssec_withdrawal::get_tx(tx, zone.id)
        .await?
        .is_some();

    let now = Utc::now();
    let diff = SignedViewDiff::compute(SignedViewParams {
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
    })
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
            bindizr_db::dnssec_key::update_max_signed_ttl_tx(tx, key.id, signed_ttl).await?;
        }
    }

    // DELs before ADDs; derived rows journal their wire RDATA, not a value.
    let mut changes = Vec::with_capacity(diff.removed.len() + diff.added.len());

    for record in &diff.removed {
        changes.push(ZoneChange {
            zone_id: zone.id,
            serial: new_serial,
            operation: ChangeOperation::Delete,
            record_name: record.name.clone(),
            record_type: JournalRecordType::Derived(record.record_type),
            record_value: None,
            record_rdata: Some(record.rdata.clone()),
            record_ttl: record.ttl,
            record_priority: None,
        });
    }

    for record in &diff.added {
        changes.push(ZoneChange {
            zone_id: zone.id,
            serial: new_serial,
            operation: ChangeOperation::Add,
            record_name: record.name.clone(),
            record_type: JournalRecordType::Derived(record.record_type),
            record_value: None,
            record_rdata: Some(record.rdata.clone()),
            record_ttl: record.ttl,
            record_priority: None,
        });
    }

    // The derived rows and their IXFR journal commit in the caller's transaction.
    bindizr_db::zone_change::create_many_tx(tx, &changes).await?;

    let removed_record_ids: Vec<DnssecRecordId> =
        diff.removed.iter().map(|record| record.id).collect();

    bindizr_db::dnssec_record::delete_many_tx(tx, &removed_record_ids).await?;
    bindizr_db::dnssec_record::create_many_tx(tx, &diff.added).await?;

    Ok(true)
}
