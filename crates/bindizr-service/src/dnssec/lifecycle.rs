//! Turning signing on and off, moving a zone between policies, and the
//! operator's force re-sign.

use bindizr_core::dns::dnssec::generate_key;
use chrono::Utc;

use super::{DnssecService, key_layout, notify_zone, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dnssec_policy::normalize_policy_name,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DEFAULT_DNSSEC_POLICY_NAME,
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::GetDnssecStatusResponse,
    zone::ZoneService,
};

impl DnssecService {
    /// Enable DNSSEC for a zone under `policy` (the built-in `default` when
    /// omitted): generate its key(s) and sign the whole zone.
    pub async fn enable(
        caller: &Caller,
        zone_name: &str,
        policy: Option<&str>,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        let policy_name = normalize_policy_name(policy.unwrap_or(DEFAULT_DNSSEC_POLICY_NAME))?;

        let mut tx = RepositoryService::begin_tx("failed to enable DNSSEC").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let existing =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if !existing.is_empty() {
                return Err(ServiceError::dnssec_already_enabled(zone.name.as_str()));
            }
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

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response = RepositoryService::finish_tx(tx, result, "failed to enable DNSSEC").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Move a signed zone to another policy. The denial mode and key layout
    /// must match (they are fixed while signed); a different algorithm
    /// starts an algorithm rollover under the new policy.
    pub async fn set_policy(
        caller: &Caller,
        zone_name: &str,
        policy_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        let policy_name = normalize_policy_name(policy_name)?;

        let mut tx = RepositoryService::begin_tx("failed to change the DNSSEC policy").await?;
        let result = async {
            let (zone, current, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let target = RepositoryService::get_dnssec_policy_by_name_tx(
                &mut tx,
                &policy_name,
                LockLevel::Shared,
            )
            .await?
            .ok_or_else(|| ServiceError::dnssec_policy_not_found(&policy_name))?;
            if target.id == current.id {
                return build_status_tx(&mut tx, &zone, Some(&current), &keys, zone.serial).await;
            }
            // Switching the denial chain or splitting a CSK in place has no
            // safe transition; the zone goes insecure and re-enables instead.
            if target.denial != current.denial {
                return Err(ServiceError::invalid_input(format!(
                    "policy '{}' uses {} denial but zone '{}' signs with {}; the denial mode \
                     is fixed while signed, so disable DNSSEC and re-enable under the new policy",
                    target.name,
                    target.denial,
                    zone.name.as_str(),
                    current.denial
                )));
            }
            if target.split_keys != current.split_keys {
                return Err(ServiceError::invalid_input(format!(
                    "policy '{}' uses {} but zone '{}' signs with {}; the key layout is fixed \
                     while signed, so disable DNSSEC and re-enable under the new policy",
                    target.name,
                    key_layout(target.split_keys),
                    zone.name.as_str(),
                    key_layout(current.split_keys)
                )));
            }

            let keys = if keys.iter().any(|key| key.algorithm != target.algorithm) {
                Self::start_algorithm_rollover_tx(&mut tx, &zone, &target, keys).await?
            } else {
                keys
            };
            RepositoryService::update_zone_dnssec_policy_id_tx(&mut tx, zone.id, Some(target.id))
                .await?;
            let zone = Zone {
                dnssec_policy_id: Some(target.id),
                ..zone
            };

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &target, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&target), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to change the DNSSEC policy").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Disable DNSSEC for a zone. The caller is responsible for the
    /// going-insecure order: remove the parent DS and wait out its TTL first,
    /// or validating resolvers read the zone as bogus.
    pub async fn disable(caller: &Caller, zone_name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to disable DNSSEC").await?;
        let result = async {
            let (zone, _, _) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

            let derived =
                RepositoryService::list_dnssec_records_tx(&mut tx, zone.id, LockLevel::None)
                    .await?;

            let new_serial = generate_serial(Some(zone.serial))?;
            // Journal a DEL for every derived row; they carry wire RDATA, not
            // a value.
            let changes: Vec<ZoneChange> = derived
                .iter()
                .map(|row| ZoneChange {
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
                })
                .collect();
            RepositoryService::create_zone_journal_tx(&mut tx, &changes).await?;
            RepositoryService::delete_dnssec_records_by_zone_id_tx(&mut tx, zone.id).await?;
            RepositoryService::delete_dnssec_keys_by_zone_id_tx(&mut tx, zone.id).await?;
            RepositoryService::delete_dnssec_withdrawal_tx(&mut tx, zone.id).await?;
            RepositoryService::update_zone_dnssec_policy_id_tx(&mut tx, zone.id, None).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            Ok(zone.name.as_str().to_string())
        }
        .await;
        let zone_name =
            RepositoryService::finish_tx(tx, result, "failed to disable DNSSEC").await?;

        notify_zone(&zone_name).await;
        Ok(())
    }

    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure.
    pub async fn withdraw(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to withdraw the parent DS").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some()
            {
                return Err(ServiceError::invalid_input(
                    "the DS withdrawal is already published",
                ));
            }
            RepositoryService::create_dnssec_withdrawal_tx(&mut tx, zone.id).await?;

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to withdraw the parent DS").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Take back a published DS withdrawal: the per-key CDS/CDNSKEY set
    /// returns on the next signing pass.
    pub async fn withdraw_cancel(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to cancel the DS withdrawal").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_none()
            {
                return Err(ServiceError::invalid_input("no DS withdrawal is published"));
            }
            RepositoryService::delete_dnssec_withdrawal_tx(&mut tx, zone.id).await?;

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to cancel the DS withdrawal").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Re-sign a zone from scratch, discarding stored signatures (recovery
    /// hatch when stored state is doubted).
    pub async fn sign(caller: &Caller, zone_name: &str) -> Result<(), ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to sign zone").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, true).await?;
            Ok(zone.name.as_str().to_string())
        }
        .await;
        let zone_name = RepositoryService::finish_tx(tx, result, "failed to sign zone").await?;

        notify_zone(&zone_name).await;
        Ok(())
    }
}
