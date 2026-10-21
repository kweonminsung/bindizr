//! Per-zone DNSSEC maintenance transactions for signing and rollover.

use bindizr_core::{
    dns::{dnssec::SigningPass, name::ZoneName},
    model::{
        dnssec_key::{DnssecKey, DnssecKeyId, DnssecKeyRole, DnssecKeyState},
        zone::ZoneId,
    },
};
use bindizr_db::LockLevel;
use chrono::{DateTime, Utc};

use crate::{
    Context,
    change::ChangeOrigin,
    dnssec::{self, rollover::promotable_sep_key_ids},
    error::ServiceError,
    transaction,
    types::Holddown,
};

/// Re-sign a zone transactionally, advancing its serial only for changed signatures.
/// Return `None` if the zone is gone, unsigned, or needs no new signatures.
pub(crate) async fn resign_zone_by_zone_id(
    cx: &Context,
    zone_id: ZoneId,
) -> Result<Option<ZoneName>, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to sign zone").await?;
    let result: Result<_, ServiceError> = async {
        let Some(signed) =
            dnssec::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };

        if dnssec::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            &ChangeOrigin::system(),
        )
        .await?
        .is_none()
        {
            return Ok(None);
        }

        Ok(Some(signed.zone.name.clone()))
    }
    .await;
    let changed = transaction::finish_tx(tx, result, "failed to sign zone").await?;

    if changed.is_some() {
        cx.metrics().track_serial_bumps(1);
    }

    Ok(changed)
}

/// Pre-publish a replacement for a zone's lifetime-expired ZSK in its own
/// transaction. `None` when the state moved on concurrently.
pub(crate) async fn start_zsk_rollover_by_zone_id(
    cx: &Context,
    zone_id: ZoneId,
) -> Result<Option<ZoneName>, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to start key rollover").await?;
    let result: Result<_, ServiceError> = async {
        let Some(mut signed) =
            dnssec::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };

        if signed.policy.zsk_lifetime_days.as_days() == 0 {
            return Ok(None);
        }

        let cutoff = Utc::now() - signed.policy.zsk_lifetime_days.to_duration();

        if signed
            .keys
            .iter()
            .any(|key| key.state != DnssecKeyState::Active)
        {
            return Ok(None);
        }

        let Some(template) = signed
            .keys
            .iter()
            .find(|key| key.role == DnssecKeyRole::Zsk && key.state_changed_at < cutoff)
        else {
            return Ok(None);
        };

        let new_key =
            dnssec::publish_replacement_key_tx(&mut tx, &signed.zone, template, template.algorithm)
                .await?;
        signed.keys.push(new_key);

        let serial = dnssec::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            &ChangeOrigin::system(),
        )
        .await?;

        Ok(serial.map(|_| signed.zone.name.clone()))
    }
    .await;
    let changed = transaction::finish_tx(tx, result, "failed to start key rollover").await?;

    if changed.is_some() {
        cx.metrics().track_serial_bumps(1);
    }

    Ok(changed)
}

/// Promote a zone's hold-down-expired pre-published ZSKs in its own
/// transaction. `None` when the state moved on concurrently.
pub(crate) async fn promote_zsks_by_zone_id(
    cx: &Context,
    zone_id: ZoneId,
) -> Result<Option<ZoneName>, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to advance key rollover").await?;
    let result: Result<_, ServiceError> = async {
        let Some(mut signed) =
            dnssec::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };

        let now = Utc::now();
        let due: Vec<DnssecKeyId> = signed
            .keys
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

        // ZSKs carry no DS at the parent, so nothing outside the zone gates them.
        signed.keys =
            dnssec::promote_published_keys_tx(&mut tx, &signed.zone, signed.keys, &due, None)
                .await?;

        let serial = dnssec::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            &ChangeOrigin::system(),
        )
        .await?;

        Ok(serial.map(|_| signed.zone.name.clone()))
    }
    .await;
    let changed = transaction::finish_tx(tx, result, "failed to advance key rollover").await?;

    if changed.is_some() {
        cx.metrics().track_serial_bumps(1);
    }

    Ok(changed)
}

/// Advance KSK/CSK rollover after parent-DS confirmation.
/// Return `None` while the DS is absent or the parent is unreachable.
pub(crate) async fn promote_sep_keys_by_zone_id(
    cx: &Context,
    zone_id: ZoneId,
) -> Result<Option<ZoneName>, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to advance key rollover").await?;
    let result: Result<_, ServiceError> = async {
        let Some(mut signed) =
            dnssec::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };

        // The same rule `ds-seen` applies, minus the errors it reports.
        let Ok(awaiting) = promotable_sep_key_ids(&signed, Holddown::Wait) else {
            return Ok(None);
        };

        let delegation = match dnssec::probe_delegation(cx, &signed).await {
            Ok(delegation) => delegation,
            Err(error) => {
                log::warn!(
                    "Parent of zone {} could not be asked for its DS, so the rollover waits: {}",
                    signed.zone.name.as_str(),
                    error
                );
                return Ok(None);
            }
        };

        // Every awaiting key, like `ds-seen`: a parent still propagating the
        // change must not move the rollover on a partial answer.
        let confirmed = delegation
            .keys
            .iter()
            .filter(|key| awaiting.contains(&key.id));

        if !confirmed.clone().all(|key| key.ds_published) {
            if confirmed.clone().any(|key| key.ds_digest_unsupported) {
                log::warn!(
                    "Parent of zone {} answers only in a DS digest bindizr cannot compute, so \
                     the rollover waits",
                    signed.zone.name.as_str()
                );
            }

            return Ok(None);
        }

        signed.keys = dnssec::promote_published_keys_tx(
            &mut tx,
            &signed.zone,
            signed.keys,
            &awaiting,
            delegation.ds_ttl,
        )
        .await?;
        let serial = dnssec::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            &ChangeOrigin::system(),
        )
        .await?;

        Ok(serial.map(|_| signed.zone.name.clone()))
    }
    .await;
    let changed = transaction::finish_tx(tx, result, "failed to advance key rollover").await?;

    if changed.is_some() {
        cx.metrics().track_serial_bumps(1);
    }

    Ok(changed)
}

/// Select retired keys past hold-down, retaining a signer per algorithm unless all leave together.
/// RFC 6840, Section 5.11 keeps an algorithm's DNSKEYs and signatures together.
fn removable_key_ids(keys: &[DnssecKey], now: DateTime<Utc>) -> Vec<DnssecKeyId> {
    keys.iter()
        .filter(|key| {
            if key.state != DnssecKeyState::Retired || key.eligible_at > now {
                return false;
            }

            let another_key_signs_data = keys.iter().any(|other| {
                matches!(other.role, DnssecKeyRole::Csk | DnssecKeyRole::Zsk)
                    && other.state == DnssecKeyState::Active
                    && other.algorithm == key.algorithm
            });

            another_key_signs_data
                || keys
                    .iter()
                    .filter(|other| other.algorithm == key.algorithm)
                    .all(|other| other.state == DnssecKeyState::Retired && other.eligible_at <= now)
        })
        .map(|key| key.id)
        .collect()
}

/// Prune a zone's hold-down-expired retired keys in its own transaction.
/// `None` when nothing was removable, or when removing would leave no key.
pub(crate) async fn prune_retired_keys_by_zone_id(
    cx: &Context,
    zone_id: ZoneId,
) -> Result<Option<ZoneName>, ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to remove retired keys").await?;
    let result: Result<_, ServiceError> = async {
        let Some(mut signed) =
            dnssec::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive).await?
        else {
            return Ok(None);
        };

        let removable = removable_key_ids(&signed.keys, Utc::now());

        // Decided before any row goes: taking every key would leave the signed
        // records with no DNSKEY to validate them.
        if removable.is_empty() || removable.len() == signed.keys.len() {
            return Ok(None);
        }

        let mut remaining = Vec::with_capacity(signed.keys.len());

        for key in std::mem::take(&mut signed.keys) {
            if removable.contains(&key.id) {
                bindizr_db::dnssec_key::delete_tx(&mut tx, key.id).await?;
            } else {
                remaining.push(key);
            }
        }

        signed.keys = remaining;

        let serial = dnssec::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            &ChangeOrigin::system(),
        )
        .await?;

        Ok(serial.map(|_| signed.zone.name.clone()))
    }
    .await;
    let changed = transaction::finish_tx(tx, result, "failed to remove retired keys").await?;

    if changed.is_some() {
        cx.metrics().track_serial_bumps(1);
    }

    Ok(changed)
}

#[cfg(test)]
mod tests;
