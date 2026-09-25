//! Turning signing on and off, moving a zone between policies, and the
//! operator's force re-sign.

use bindizr_core::dns::dnssec::generate_key;
use chrono::Utc;

use super::{DnssecService, parent_ns_addrs::normalize_parent_ns_addrs, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dnssec::SignedZone,
    dnssec_policy::normalize_policy_name,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKeyRole, DnssecKeyState},
        dnssec_policy::{DEFAULT_DNSSEC_POLICY_NAME, DnssecPolicy},
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::DnssecStatusResponse,
    zone::ZoneService,
};

/// Whether a signed zone can move onto `target` without going insecure first.
/// The key layout has no safe in-place transition. The algorithm does, through
/// a rollover; so does the denial chain, since every algorithm bindizr signs
/// with is NSEC3-capable (RFC 5155, Section 2) and the whole chain is replaced
/// under one serial.
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

impl DnssecService {
    /// Enable DNSSEC for a zone under `policy` (the built-in `default` when
    /// omitted): generate its key(s) and sign the whole zone. The parent
    /// nameservers are required, since every later DS check asks them.
    pub async fn enable(
        caller: &Caller,
        zone_name: &str,
        policy: Option<&str>,
        parent_ns_addrs: &[String],
    ) -> Result<DnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;
        let policy_name = normalize_policy_name(policy.unwrap_or(DEFAULT_DNSSEC_POLICY_NAME))?;
        let parent_ns_addrs = normalize_parent_ns_addrs(parent_ns_addrs)?;

        let mut tx = RepositoryService::begin_tx("failed to enable DNSSEC").await?;
        let result = async {
            // Check the unsigned state under the same lock used to install the keys.
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let existing_keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if !existing_keys.is_empty() {
                return Err(ServiceError::dnssec_already_enabled(zone.name.as_str()));
            }
            RepositoryService::update_zone_parent_ns_addrs_tx(
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
            let policy = RepositoryService::get_dnssec_policy_by_name_tx(
                &mut tx,
                &policy_name,
                LockLevel::Shared,
            )
            .await?
            .ok_or_else(|| ServiceError::dnssec_policy_not_found(&policy_name))?;

            RepositoryService::update_zone_dnssec_policy_id_tx(&mut tx, zone.id, Some(policy.id))
                .await?;
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
                let key = generate_key(
                    &zone,
                    policy.algorithm,
                    *role,
                    DnssecKeyState::Active,
                    now,
                    now,
                )
                .map_err(ServiceError::dnssec_signing_failed)?;
                keys.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);
            }
            let signed = SignedZone { zone, policy, keys };

            let new_serial =
                Self::resign_zone_tx(&mut tx, &signed, false, &caller.change_subject())
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
        let response = RepositoryService::finish_tx(tx, result, "failed to enable DNSSEC").await?;

        log::info!("event=dnssec_enable zone={}", response.zone_name);

        // Secondaries can fetch the signed view only after the transaction commits.
        crate::notify::notify_after_update(&response.zone_name).await;
        Ok(response)
    }

    /// Change a zone's signing settings in one transaction; an omitted field
    /// keeps its value. A policy move needs a signed zone; `parent_ns_addrs`
    /// replaces the parent nameservers, signed or not.
    pub async fn update_settings(
        caller: &Caller,
        zone_name: &str,
        policy: Option<&str>,
        parent_ns_addrs: Option<&[String]>,
    ) -> Result<DnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;
        if policy.is_none() && parent_ns_addrs.is_none() {
            return Err(ServiceError::invalid_input(
                "nothing to update: give a policy, parent nameserver addresses, or both",
            ));
        }
        let policy_name = policy.map(normalize_policy_name).transpose()?;
        let parent_ns_addrs = parent_ns_addrs.map(normalize_parent_ns_addrs).transpose()?;

        let mut tx = RepositoryService::begin_tx("failed to update DNSSEC settings").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let zone = match parent_ns_addrs {
                Some(parent_ns_addrs) => {
                    RepositoryService::update_zone_parent_ns_addrs_tx(
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
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

            // Parent addresses alone change no served records and need no re-signing.
            let Some(policy_name) = &policy_name else {
                let policy = Self::find_zone_policy_tx(&mut tx, &zone).await?;
                return build_status_tx(&mut tx, &zone, policy.as_ref(), &keys, zone.serial).await;
            };

            if keys.is_empty() {
                return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
            }
            let current = Self::get_zone_policy_tx(&mut tx, &zone).await?;
            let target = RepositoryService::get_dnssec_policy_by_name_tx(
                &mut tx,
                policy_name,
                LockLevel::Shared,
            )
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
                Self::start_algorithm_rollover_tx(&mut tx, &zone, &target, keys).await?
            } else {
                keys
            };
            RepositoryService::update_zone_dnssec_policy_id_tx(&mut tx, zone.id, Some(target.id))
                .await?;
            let signed = SignedZone {
                zone: Zone {
                    dnssec_policy_id: Some(target.id),
                    ..zone
                },
                policy: target,
                keys,
            };

            let new_serial =
                Self::resign_zone_tx(&mut tx, &signed, false, &caller.change_subject())
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
        let response =
            RepositoryService::finish_tx(tx, result, "failed to update DNSSEC settings").await?;

        log::info!("event=dnssec_update_settings zone={}", response.zone_name);
        // Only a policy move changes zone data; parent nameservers are not served.
        if policy_name.is_some() {
            crate::notify::notify_after_update(&response.zone_name).await;
        }
        Ok(response)
    }

    /// Disable DNSSEC for a zone. Refused while the parent still serves the
    /// zone's DS or cannot be asked, since signatures dropped under a DS make
    /// the zone bogus; `skip_ds_check` skips that check.
    pub async fn disable(
        caller: &Caller,
        zone_name: &str,
        skip_ds_check: bool,
    ) -> Result<(), ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to disable DNSSEC").await?;
        let result = async {
            let signed = Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if !skip_ds_check {
                let delegation = Self::probe_delegation(&signed).await?;
                if !delegation.ds_key_tags.is_empty() {
                    return Err(ServiceError::dnssec_ds_published(
                        signed.zone.name.as_str(),
                        &delegation.ds_key_tags,
                    ));
                }
            }

            let derived =
                RepositoryService::list_dnssec_records_tx(&mut tx, signed.zone.id, LockLevel::None)
                    .await?;

            let new_serial = generate_serial(Some(signed.zone.serial))?;
            // Journal a DEL for every derived row; they carry wire RDATA, not
            // a value.
            let changes: Vec<ZoneChange> = derived
                .iter()
                .map(|row| ZoneChange {
                    zone_id: signed.zone.id,
                    serial: new_serial,
                    operation: ChangeOperation::Del,
                    record_name: row.name.clone(),
                    record_type: JournalRecordType::Derived(row.record_type),
                    record_value: None,
                    record_rdata: Some(row.rdata.clone()),
                    record_ttl: row.ttl,
                    record_priority: None,
                    derived: true,
                })
                .collect();
            RepositoryService::create_zone_changes_tx(&mut tx, &changes).await?;
            RepositoryService::delete_dnssec_records_by_zone_id_tx(&mut tx, signed.zone.id).await?;
            RepositoryService::delete_dnssec_keys_by_zone_id_tx(&mut tx, signed.zone.id).await?;
            RepositoryService::delete_dnssec_withdrawal_tx(&mut tx, signed.zone.id).await?;
            RepositoryService::update_zone_dnssec_policy_id_tx(&mut tx, signed.zone.id, None)
                .await?;
            ZoneService::advance_serial_tx(
                &mut tx,
                &signed.zone,
                new_serial,
                &caller.change_subject(),
            )
            .await?;

            Ok(signed.zone.name.as_str().to_string())
        }
        .await;
        let zone_name =
            RepositoryService::finish_tx(tx, result, "failed to disable DNSSEC").await?;

        if skip_ds_check {
            log::warn!("event=dnssec_disable_ds_check_skipped zone={}", zone_name);
        }
        log::info!("event=dnssec_disable zone={}", zone_name);
        crate::notify::notify_after_update(&zone_name).await;
        Ok(())
    }

    /// Re-sign a zone from scratch, discarding stored signatures (recovery
    /// hatch when stored state is doubted).
    pub async fn sign(caller: &Caller, zone_name: &str) -> Result<(), ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to sign zone").await?;
        let result = async {
            let signed = Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            Self::resign_zone_tx(&mut tx, &signed, true, &caller.change_subject()).await?;
            Ok(signed.zone.name.as_str().to_string())
        }
        .await;
        let zone_name = RepositoryService::finish_tx(tx, result, "failed to sign zone").await?;

        log::info!("event=dnssec_sign zone={}", zone_name);
        crate::notify::notify_after_update(&zone_name).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
