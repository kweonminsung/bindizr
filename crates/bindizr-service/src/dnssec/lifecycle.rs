//! Turning signing on and off, and the operator's force re-sign.

use chrono::Utc;

use super::{DnssecService, derived_changes, generate_key, notify_zone, status::build_status};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKeyRole, DnssecKeyState},
        zone::{DnssecDenial, Zone},
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::GetDnssecStatusResponse,
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
                let key = generate_key(&zone, algorithm, *role, DnssecKeyState::Active, now, now)?;
                keys.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);
            }

            // Signing changes the zone content secondaries hold, so it rides the
            // same serial/IXFR mechanics as any record change.
            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = Self::earliest_expiry_tx(&mut tx, zone.id).await?;
            build_status(&zone, denial, &keys, earliest, new_serial)
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
            let changes = derived_changes(zone.id, new_serial, &derived, &[]);
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
}
