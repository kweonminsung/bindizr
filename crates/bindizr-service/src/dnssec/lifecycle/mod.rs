//! Turning signing on and off, moving a zone between policies, and the
//! operator's force re-sign.

use bindizr_core::dns::dnssec::SigningPass;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::audit_log::{AuditEntity, AuditOperation};
use bindizr_core::model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState};
use bindizr_core::model::dnssec_policy::{DEFAULT_DNSSEC_POLICY_NAME, DnssecPolicy};
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_core::model::zone_change::{ChangeOperation, JournalRecordType, ZoneChange};
use bindizr_db::LockLevel;
use chrono::Utc;

use crate::authorization::Caller;
use crate::dnssec::{SignedZone, parent_ns_addrs, status};
use crate::error::ServiceError;
use crate::types::{
    DnssecStatusResponse, DsCheck, EnableDnssecRequest, UpdateDnssecSettingsRequest,
};
use crate::{Context, audit, dnssec, dnssec_policy, notify, serial, transaction, zone};

/// Validate a policy move: layout changes require disabling DNSSEC first; algorithms use rollover.
/// Denial changes are atomic because all supported algorithms sign NSEC3 (RFC 5702, Section 2; RFC 6605, Section 2; RFC 8080, Section 2).
fn validate_policy_move(
    zone: &Zone,
    current: &DnssecPolicy,
    target: &DnssecPolicy,
) -> Result<(), ServiceError> {
    if target.split_keys != current.split_keys {
        return Err(ServiceError::invalid_input(format!(
            "policy '{}' uses {} but zone '{}' signs with {}; the key layout is fixed while \
             signed, so disable DNSSEC and re-enable under the new policy",
            target.name,
            target.key_layout(),
            zone.name,
            current.key_layout()
        )));
    }

    Ok(())
}

/// Enable DNSSEC and sign the zone using `policy_name` (default: `default`).
/// Parent nameservers are required for subsequent DS checks.
pub async fn enable(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &EnableDnssecRequest,
) -> Result<DnssecStatusResponse, ServiceError> {
    let policy_name = dnssec_policy::normalize_name(
        request
            .policy_name
            .as_deref()
            .unwrap_or(DEFAULT_DNSSEC_POLICY_NAME),
    )?;
    let parent_ns_addrs = parent_ns_addrs::normalize(&request.parent_ns_addrs)?;

    let mut tx = transaction::begin_tx(cx, "failed to enable DNSSEC").await?;

    let apply_result: Result<_, ServiceError> = async {
        // Check the unsigned state under the same lock used to install the keys.
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::DnssecManage, &zone)?;

        let existing_keys =
            bindizr_db::dnssec_key::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;

        if !existing_keys.is_empty() {
            return Err(ServiceError::dnssec_already_enabled(&zone.name));
        }

        // Shared: a concurrent delete of the policy must wait for the FK
        // reference this transaction is about to write.
        let policy =
            bindizr_db::dnssec_policy::get_by_name_tx(&mut tx, &policy_name, LockLevel::Shared)
                .await?
                .ok_or_else(|| ServiceError::dnssec_policy_not_found(&policy_name))?;

        let zone = Zone {
            parent_ns_addrs: Some(parent_ns_addrs),
            dnssec_policy_id: Some(policy.id),
            ..zone
        };

        // Create every signer role before building the zone's first signed view.
        let now = Utc::now();
        let roles: &[DnssecKeyRole] = if policy.split_keys {
            &[DnssecKeyRole::Ksk, DnssecKeyRole::Zsk]
        } else {
            &[DnssecKeyRole::Csk]
        };
        let mut keys = Vec::with_capacity(roles.len());

        for role in roles {
            let key = DnssecKey::generate(
                &zone,
                policy.algorithm,
                *role,
                DnssecKeyState::Active,
                now,
                now,
            )
            .map_err(ServiceError::dnssec_signing_failed)?;
            keys.push(key);
        }

        bindizr_db::zone::update_parent_ns_addrs_tx(
            &mut tx,
            zone.id,
            zone.parent_ns_addrs.as_deref(),
        )
        .await?;
        bindizr_db::zone::update_dnssec_policy_id_tx(&mut tx, zone.id, Some(policy.id)).await?;

        let mut stored = Vec::with_capacity(keys.len());

        for key in keys {
            stored.push(bindizr_db::dnssec_key::create_tx(&mut tx, key).await?);
        }

        let signed = SignedZone {
            zone,
            policy,
            keys: stored,
        };

        let new_serial = dnssec::resign_zone_tx(
            &mut tx,
            &signed,
            SigningPass::Refresh,
            caller.change_origin(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        let response = status::lookup_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await?;

        Ok((response, new_serial != signed.zone.serial))
    }
    .await;

    let (response, changed) =
        transaction::finish_tx(tx, apply_result, "failed to enable DNSSEC").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
    }

    log::info!("event=dnssec_enable zone={}", response.zone_name);

    // Secondaries can fetch the signed view only after the transaction commits.
    if changed {
        notify::notify_after_update(cx, zone_name).await;
    }

    Ok(response)
}

/// Change a zone's signing settings in one transaction; an omitted field
/// keeps its value. A policy move needs a signed zone; `parent_ns_addrs`
/// replaces the parent nameservers, signed or not.
pub async fn update_settings(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &UpdateDnssecSettingsRequest,
) -> Result<DnssecStatusResponse, ServiceError> {
    if request.policy_name.is_none() && request.parent_ns_addrs.is_none() {
        return Err(ServiceError::invalid_input(
            "nothing to update: give a policy, parent nameserver addresses, or both",
        ));
    }

    let policy_name = request
        .policy_name
        .as_deref()
        .map(dnssec_policy::normalize_name)
        .transpose()?;
    let parent_ns_addrs = request
        .parent_ns_addrs
        .as_deref()
        .map(parent_ns_addrs::normalize)
        .transpose()?;

    let mut tx = transaction::begin_tx(cx, "failed to update DNSSEC settings").await?;

    let apply_result: Result<_, ServiceError> = async {
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let caller = &caller.reauthenticate_tx(&mut tx).await?;
        caller.authorize_zone_action(Action::DnssecManage, &zone)?;

        let keys = bindizr_db::dnssec_key::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        let (policy, policy_change) = match &policy_name {
            Some(policy_name) => {
                if keys.is_empty() {
                    return Err(ServiceError::dnssec_not_enabled(&zone.name));
                }

                let current = dnssec::lookup_zone_policy_tx(&mut tx, &zone).await?;
                let target = bindizr_db::dnssec_policy::get_by_name_tx(
                    &mut tx,
                    policy_name,
                    LockLevel::Shared,
                )
                .await?
                .ok_or_else(|| ServiceError::dnssec_policy_not_found(policy_name))?;
                validate_policy_move(&zone, &current, &target)?;
                let policy_change = audit::changed("policy", &current.name, &target.name);

                (Some(target), policy_change)
            }
            None => (dnssec::find_zone_policy_tx(&mut tx, &zone).await?, None),
        };
        let parent_ns_addrs_change = parent_ns_addrs.as_deref().and_then(|next| {
            audit::changed(
                "parent_ns_addrs",
                zone.parent_ns_addrs.as_deref().unwrap_or("none"),
                next,
            )
        });
        let policy_changed = policy.as_ref().map(|policy| policy.id) != zone.dnssec_policy_id;
        let candidate = Zone {
            parent_ns_addrs: parent_ns_addrs.clone().or(zone.parent_ns_addrs),
            dnssec_policy_id: policy.as_ref().map(|policy| policy.id),
            ..zone
        };

        let mut new_serial = candidate.serial;
        let mut keys = keys;

        if let Some(policy) = &policy
            && policy_changed
        {
            if keys.iter().any(|key| key.algorithm != policy.algorithm) {
                keys =
                    dnssec::start_algorithm_rollover_tx(&mut tx, &candidate, policy, keys).await?;
            }

            bindizr_db::zone::update_dnssec_policy_id_tx(&mut tx, candidate.id, Some(policy.id))
                .await?;

            let signed = SignedZone {
                zone: candidate.clone(),
                policy: policy.clone(),
                keys,
            };

            new_serial = dnssec::resign_zone_tx(
                &mut tx,
                &signed,
                SigningPass::Refresh,
                caller.change_origin(),
            )
            .await?
            .unwrap_or(candidate.serial);

            keys = signed.keys;
        }

        if parent_ns_addrs.is_some() {
            bindizr_db::zone::update_parent_ns_addrs_tx(
                &mut tx,
                candidate.id,
                candidate.parent_ns_addrs.as_deref(),
            )
            .await?;
        }

        // A version holds records, never these settings, so the audit log keeps them.
        audit::save_tx(
            &mut tx,
            AuditEntity::Zone,
            candidate.name.as_str(),
            AuditOperation::Update,
            audit::join_changes([policy_change, parent_ns_addrs_change]),
            caller.change_origin(),
        )
        .await?;

        let response =
            status::lookup_status_tx(&mut tx, &candidate, policy.as_ref(), &keys, new_serial)
                .await?;

        Ok((response, new_serial != candidate.serial))
    }
    .await;

    let (response, changed) =
        transaction::finish_tx(tx, apply_result, "failed to update DNSSEC settings").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
    }

    log::info!("event=dnssec_update_settings zone={}", response.zone_name);

    // Only a policy move changes zone data; parent nameservers are not served.
    if changed {
        notify::notify_after_update(cx, zone_name).await;
    }

    Ok(response)
}

/// Disable DNSSEC, refusing a published DS or failed parent probe unless `ds_check` skips it.
/// Removing signatures while a parent DS remains makes the zone bogus.
pub async fn disable(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    ds_check: DsCheck,
) -> Result<(), ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to disable DNSSEC").await?;

    let apply_result: Result<_, ServiceError> = async {
        let signed = dnssec::get_signed_zone_tx(
            &mut tx,
            caller,
            Action::DnssecManage,
            zone_name,
            LockLevel::Exclusive,
        )
        .await?;

        if ds_check == DsCheck::Probe {
            let delegation = dnssec::probe_delegation(cx, &signed).await?;

            if !delegation.ds_key_tags.is_empty() {
                return Err(ServiceError::dnssec_ds_published(
                    &signed.zone.name,
                    &delegation.ds_key_tags,
                ));
            }
        }

        let derived =
            bindizr_db::dnssec_record::list_tx(&mut tx, signed.zone.id, LockLevel::Unlocked)
                .await?;

        let new_serial = serial::generate_serial(Some(signed.zone.serial));

        // Journal a DEL for every derived row; they carry wire RDATA, not
        // a value.
        let changes: Vec<ZoneChange> = derived
            .iter()
            .map(|record| ZoneChange {
                zone_id: signed.zone.id,
                serial: new_serial,
                operation: ChangeOperation::Delete,
                record_name: record.name.clone(),
                record_type: JournalRecordType::Derived(record.record_type),
                record_value: None,
                record_rdata: Some(record.rdata.clone()),
                record_ttl: record.ttl,
                record_priority: None,
                derived: true,
            })
            .collect();

        bindizr_db::zone_change::create_many_tx(&mut tx, &changes).await?;
        bindizr_db::dnssec_record::delete_by_zone_id_tx(&mut tx, signed.zone.id).await?;
        bindizr_db::dnssec_key::delete_by_zone_id_tx(&mut tx, signed.zone.id).await?;
        bindizr_db::dnssec_withdrawal::delete_tx(&mut tx, signed.zone.id).await?;
        bindizr_db::zone::update_dnssec_policy_id_tx(&mut tx, signed.zone.id, None).await?;
        zone::advance_serial_tx(&mut tx, &signed.zone, new_serial, caller.change_origin()).await?;

        Ok(())
    }
    .await;

    transaction::finish_tx(tx, apply_result, "failed to disable DNSSEC").await?;

    cx.metrics().track_serial_bumps(1);

    if ds_check == DsCheck::Skip {
        log::warn!("event=dnssec_disable_ds_check_skipped zone={zone_name}");
    }

    log::info!("event=dnssec_disable zone={zone_name}");

    notify::notify_after_update(cx, zone_name).await;

    Ok(())
}

/// Re-sign a zone from scratch, discarding stored signatures (recovery
/// hatch when stored state is doubted).
pub async fn sign(cx: &Context, caller: &Caller, zone_name: &ZoneName) -> Result<(), ServiceError> {
    let mut tx = transaction::begin_tx(cx, "failed to sign zone").await?;

    let apply_result: Result<_, ServiceError> = async {
        let signed = dnssec::get_signed_zone_tx(
            &mut tx,
            caller,
            Action::DnssecManage,
            zone_name,
            LockLevel::Exclusive,
        )
        .await?;
        let changed =
            dnssec::resign_zone_tx(&mut tx, &signed, SigningPass::Full, caller.change_origin())
                .await?
                .is_some();

        Ok(changed)
    }
    .await;

    let changed = transaction::finish_tx(tx, apply_result, "failed to sign zone").await?;

    if changed {
        cx.metrics().track_serial_bumps(1);
    }

    log::info!("event=dnssec_sign zone={zone_name}");

    if changed {
        notify::notify_after_update(cx, zone_name).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests;
