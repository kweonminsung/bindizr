//! Turning signing on and off, moving a zone between policies, and the
//! operator's force re-sign.

use bindizr_core::{
    dns::{dnssec::SigningPass, name::ZoneName},
    model::dnssec_key::DnssecKey,
};
use bindizr_db::LockLevel;
use chrono::Utc;

use super::{parent_ns_addrs::normalize_parent_ns_addrs, status::build_status_tx};
use crate::{
    Context,
    authorization::Caller,
    dnssec::SignedZone,
    dnssec_policy::normalize_policy_name,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKeyRole, DnssecKeyState},
        dnssec_policy::{DEFAULT_DNSSEC_POLICY_NAME, DnssecPolicy},
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    serial::generate_serial,
    transaction,
    types::{DnssecStatusResponse, DsCheck, EnableDnssecRequest, UpdateDnssecSettingsRequest},
    zone,
};

/// Check whether `target` preserves signing: layout changes require disabling it first.
/// Algorithms use rollover; denial chains change atomically under one serial because
/// all supported signing algorithms support NSEC3 (RFC 5155, Section 2).
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
            zone.name.as_str(),
            current.key_layout()
        )));
    }

    Ok(())
}

/// Enable DNSSEC for a zone under `policy_name` (the built-in `default`
/// when omitted): generate its key(s) and sign the whole zone. The parent
/// nameservers are required, since every later DS check asks them.
pub async fn enable(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &EnableDnssecRequest,
) -> Result<DnssecStatusResponse, ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;
    let policy_name = normalize_policy_name(
        request
            .policy_name
            .as_deref()
            .unwrap_or(DEFAULT_DNSSEC_POLICY_NAME),
    )?;
    let parent_ns_addrs = normalize_parent_ns_addrs(&request.parent_ns_addrs)?;

    let mut tx = transaction::begin_tx(cx, "failed to enable DNSSEC").await?;
    let result = async {
        // Check the unsigned state under the same lock used to install the keys.
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let existing_keys =
            bindizr_db::dnssec_key::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;
        if !existing_keys.is_empty() {
            return Err(ServiceError::dnssec_already_enabled(zone.name.as_str()));
        }
        bindizr_db::zone::update_parent_ns_addrs_tx(
            &mut tx,
            zone.id,
            Some(parent_ns_addrs.as_str()),
        )
        .await?;
        let zone = Zone {
            parent_ns_addrs: Some(parent_ns_addrs),
            ..zone
        };
        // Shared: a concurrent delete of the policy must wait for the FK
        // reference this transaction is about to write.
        let policy =
            bindizr_db::dnssec_policy::get_by_name_tx(&mut tx, &policy_name, LockLevel::Shared)
                .await?
                .ok_or_else(|| ServiceError::dnssec_policy_not_found(&policy_name))?;

        bindizr_db::zone::update_dnssec_policy_id_tx(&mut tx, zone.id, Some(policy.id)).await?;
        let zone = Zone {
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
            keys.push(bindizr_db::dnssec_key::create_tx(&mut tx, key).await?);
        }
        let signed = SignedZone { zone, policy, keys };

        let new_serial = super::resign_zone_tx(
            &mut tx,
            cx,
            &signed,
            SigningPass::Refresh,
            &caller.change_subject(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        build_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await
    }
    .await;
    let response = transaction::finish_tx(tx, result, "failed to enable DNSSEC").await?;

    log::info!("event=dnssec_enable zone={}", response.zone_name);

    // Secondaries can fetch the signed view only after the transaction commits.
    crate::notify::notify_after_update(cx, zone_name).await;
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
    caller.authorize_global("manage DNSSEC signing")?;
    if request.policy_name.is_none() && request.parent_ns_addrs.is_none() {
        return Err(ServiceError::invalid_input(
            "nothing to update: give a policy, parent nameserver addresses, or both",
        ));
    }
    let policy_name = request
        .policy_name
        .as_deref()
        .map(normalize_policy_name)
        .transpose()?;
    let parent_ns_addrs = request
        .parent_ns_addrs
        .as_deref()
        .map(normalize_parent_ns_addrs)
        .transpose()?;

    let mut tx = transaction::begin_tx(cx, "failed to update DNSSEC settings").await?;
    let result = async {
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let zone = match parent_ns_addrs {
            Some(parent_ns_addrs) => {
                bindizr_db::zone::update_parent_ns_addrs_tx(
                    &mut tx,
                    zone.id,
                    Some(parent_ns_addrs.as_str()),
                )
                .await?;
                Zone {
                    parent_ns_addrs: Some(parent_ns_addrs),
                    ..zone
                }
            }
            None => zone,
        };
        let keys = bindizr_db::dnssec_key::list_tx(&mut tx, zone.id, LockLevel::Unlocked).await?;

        // Parent addresses alone change no served records and need no re-signing.
        let Some(policy_name) = &policy_name else {
            let policy = super::find_zone_policy_tx(&mut tx, &zone).await?;
            return build_status_tx(&mut tx, &zone, policy.as_ref(), &keys, zone.serial).await;
        };

        if keys.is_empty() {
            return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
        }
        let current = super::lookup_zone_policy_tx(&mut tx, &zone).await?;
        let target =
            bindizr_db::dnssec_policy::get_by_name_tx(&mut tx, policy_name, LockLevel::Shared)
                .await?
                .ok_or_else(|| ServiceError::dnssec_policy_not_found(policy_name))?;

        // Selecting the current policy leaves the existing signed view intact.
        if target.id == current.id {
            return build_status_tx(&mut tx, &zone, Some(&current), &keys, zone.serial).await;
        }
        validate_policy_move(&zone, &current, &target)?;

        // An algorithm change pre-publishes replacements before applying and
        // signing under the target policy in this transaction.
        let keys = if keys.iter().any(|key| key.algorithm != target.algorithm) {
            super::start_algorithm_rollover_tx(&mut tx, &zone, &target, keys).await?
        } else {
            keys
        };
        bindizr_db::zone::update_dnssec_policy_id_tx(&mut tx, zone.id, Some(target.id)).await?;
        let signed = SignedZone {
            zone: Zone {
                dnssec_policy_id: Some(target.id),
                ..zone
            },
            policy: target,
            keys,
        };

        let new_serial = super::resign_zone_tx(
            &mut tx,
            cx,
            &signed,
            SigningPass::Refresh,
            &caller.change_subject(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        build_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await
    }
    .await;
    let response = transaction::finish_tx(tx, result, "failed to update DNSSEC settings").await?;

    log::info!("event=dnssec_update_settings zone={}", response.zone_name);
    // Only a policy move changes zone data; parent nameservers are not served.
    if policy_name.is_some() {
        crate::notify::notify_after_update(cx, zone_name).await;
    }
    Ok(response)
}

/// Disable DNSSEC for a zone. Refused while the parent still serves the
/// zone's DS or cannot be asked, since signatures dropped under a DS make
/// the zone bogus; `ds_check` may skip that check.
pub async fn disable(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    ds_check: DsCheck,
) -> Result<(), ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;

    let mut tx = transaction::begin_tx(cx, "failed to disable DNSSEC").await?;
    let result = async {
        let signed = super::lookup_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        if ds_check == DsCheck::Probe {
            let delegation = super::probe_delegation(cx, &signed).await?;
            if !delegation.ds_key_tags.is_empty() {
                return Err(ServiceError::dnssec_ds_published(
                    signed.zone.name.as_str(),
                    &delegation.ds_key_tags,
                ));
            }
        }

        let derived =
            bindizr_db::dnssec_record::list_tx(&mut tx, signed.zone.id, LockLevel::Unlocked)
                .await?;

        let new_serial = generate_serial(Some(signed.zone.serial))?;
        // Journal a DEL for every derived row; they carry wire RDATA, not
        // a value.
        let changes: Vec<ZoneChange> = derived
            .iter()
            .map(|row| ZoneChange {
                zone_id: signed.zone.id,
                serial: new_serial,
                operation: ChangeOperation::Delete,
                record_name: row.name.clone(),
                record_type: JournalRecordType::Derived(row.record_type),
                record_value: None,
                record_rdata: Some(row.rdata.clone()),
                record_ttl: row.ttl,
                record_priority: None,
                derived: true,
            })
            .collect();
        bindizr_db::zone_change::create_many_tx(&mut tx, &changes).await?;
        bindizr_db::dnssec_record::delete_by_zone_id_tx(&mut tx, signed.zone.id).await?;
        bindizr_db::dnssec_key::delete_by_zone_id_tx(&mut tx, signed.zone.id).await?;
        bindizr_db::dnssec_withdrawal::delete_tx(&mut tx, signed.zone.id).await?;
        bindizr_db::zone::update_dnssec_policy_id_tx(&mut tx, signed.zone.id, None).await?;
        zone::advance_serial_tx(
            &mut tx,
            cx,
            &signed.zone,
            new_serial,
            &caller.change_subject(),
        )
        .await?;

        Ok(signed.zone.name.clone())
    }
    .await;
    let zone_name = transaction::finish_tx(tx, result, "failed to disable DNSSEC").await?;

    if ds_check == DsCheck::Skip {
        log::warn!("event=dnssec_disable_ds_check_skipped zone={}", zone_name);
    }
    log::info!("event=dnssec_disable zone={}", zone_name);
    crate::notify::notify_after_update(cx, &zone_name).await;
    Ok(())
}

/// Re-sign a zone from scratch, discarding stored signatures (recovery
/// hatch when stored state is doubted).
pub async fn sign(cx: &Context, caller: &Caller, zone_name: &ZoneName) -> Result<(), ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;

    let mut tx = transaction::begin_tx(cx, "failed to sign zone").await?;
    let result: Result<_, ServiceError> = async {
        let signed = super::lookup_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        super::resign_zone_tx(
            &mut tx,
            cx,
            &signed,
            SigningPass::Full,
            &caller.change_subject(),
        )
        .await?;
        Ok(signed.zone.name.clone())
    }
    .await;
    let zone_name = transaction::finish_tx(tx, result, "failed to sign zone").await?;

    log::info!("event=dnssec_sign zone={}", zone_name);
    crate::notify::notify_after_update(cx, &zone_name).await;
    Ok(())
}

#[cfg(test)]
mod tests;
