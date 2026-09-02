//! Turning signing on and off, and the operator's force re-sign.

use bindizr_core::{config::bindizr_config, dns::dnssec::generate_key};
use chrono::Utc;

use super::{DnssecService, notify_zone, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKeyRole, DnssecKeyState},
        zone::{DnssecDenial, Zone},
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{GetDnssecStatusResponse, SetDnssecTimingRequest},
    zone::ZoneService,
};

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
                let key = generate_key(&zone, algorithm, *role, DnssecKeyState::Active, now, now)
                    .map_err(ServiceError::dnssec_signing_failed)?;
                keys.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);
            }

            // Signing changes the zone content secondaries hold, so it rides the
            // same serial/IXFR mechanics as any record change.
            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            build_status_tx(&mut tx, &zone, &keys, new_serial).await
        }
        .await;
        let response = RepositoryService::finish_tx(tx, result, "failed to enable DNSSEC").await?;

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
            let (zone, _) =
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

    /// Publish the RFC 8078 delete CDS/CDNSKEY pair, asking a CDS-consuming
    /// parent to drop the zone's DS: the first step of going insecure.
    pub async fn withdraw(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to withdraw the parent DS").await?;
        let result = async {
            let (zone, keys) =
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

            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            build_status_tx(&mut tx, &zone, &keys, new_serial).await
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
            let (zone, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_none()
            {
                return Err(ServiceError::invalid_input("no DS withdrawal is published"));
            }
            RepositoryService::delete_dnssec_withdrawal_tx(&mut tx, zone.id).await?;

            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            build_status_tx(&mut tx, &zone, &keys, new_serial).await
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
            let (zone, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
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

    /// Replace the zone's timing overrides; omitted fields revert to the
    /// global config. Takes effect on the next maintenance pass or re-sign.
    pub async fn set_timing(
        caller: &Caller,
        zone_name: &str,
        request: SetDnssecTimingRequest,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        for (field, value) in [
            ("signature_validity_days", request.signature_validity_days),
            ("signature_refresh_days", request.signature_refresh_days),
        ] {
            if value == Some(0) {
                return Err(ServiceError::invalid_input(format!(
                    "{} must be positive",
                    field
                )));
            }
        }
        for (field, value) in [
            ("signature_validity_days", request.signature_validity_days),
            ("signature_refresh_days", request.signature_refresh_days),
            ("zsk_lifetime_days", request.zsk_lifetime_days),
        ] {
            if value.is_some_and(|days| days > 3650) {
                return Err(ServiceError::invalid_input(format!(
                    "{} must be at most 3650",
                    field
                )));
            }
        }
        // A validity inside the re-sign window would re-sign on every pass.
        let defaults = &bindizr_config().dnssec;
        let validity = request
            .signature_validity_days
            .unwrap_or(defaults.default_signature_validity_days);
        let refresh = request
            .signature_refresh_days
            .unwrap_or(defaults.default_signature_refresh_days);
        if validity <= refresh {
            return Err(ServiceError::invalid_input(format!(
                "effective signature_validity_days ({}) must exceed signature_refresh_days ({})",
                validity, refresh
            )));
        }

        // Lookup and update share the zone lock so a concurrent rename or
        // delete/recreate cannot slip between them.
        let mut tx = RepositoryService::begin_tx("failed to update DNSSEC timing").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            RepositoryService::update_zone_dnssec_timing_tx(
                &mut tx,
                zone.id,
                request.signature_validity_days.map(|days| days as i32),
                request.signature_refresh_days.map(|days| days as i32),
                request.zsk_lifetime_days.map(|days| days as i32),
            )
            .await?;
            let zone = Zone {
                dnssec_signature_validity_days: request
                    .signature_validity_days
                    .map(|days| days as i32),
                dnssec_signature_refresh_days: request
                    .signature_refresh_days
                    .map(|days| days as i32),
                dnssec_zsk_lifetime_days: request.zsk_lifetime_days.map(|days| days as i32),
                ..zone
            };

            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            build_status_tx(&mut tx, &zone, &keys, zone.serial).await
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to update DNSSEC timing").await
    }
}
