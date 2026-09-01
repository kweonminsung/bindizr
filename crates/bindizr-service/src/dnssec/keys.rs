//! Importing and exporting raw key material in BIND key-file form. Reached
//! only over the daemon socket: private keys never transit the HTTP API.

use bindizr_core::dns::dnssec::import_key;
use chrono::Utc;

use super::{DnssecService, notify_zone, status::build_status};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::dnssec_key::DnssecKeyRole,
    repository::RepositoryService,
    serial::generate_serial,
    types::{
        DnssecKeyMaterial, ExportDnssecKeysResponse, GetDnssecStatusResponse,
        ImportDnssecKeyRequest,
    },
    zone::ZoneService,
};

impl DnssecService {
    /// The zone's keys as BIND file contents (`K*.key` / `K*.private`).
    pub async fn export_keys(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<ExportDnssecKeysResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let zone = ZoneService::get_by_name(caller, zone_name).await?;
        let mut tx = RepositoryService::begin_read_tx("failed to export DNSSEC keys").await?;
        let result = async {
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            if keys.is_empty() {
                return Err(ServiceError::dnssec_not_enabled(zone.name.as_str()));
            }
            Ok(ExportDnssecKeysResponse {
                zone_name: zone.name.as_str().to_string(),
                keys: keys
                    .iter()
                    .map(|key| DnssecKeyMaterial {
                        role: key.role.to_string(),
                        algorithm: key.algorithm.to_int(),
                        key_tag: key.key_tag,
                        dnskey_record: format!(
                            "{}. IN DNSKEY {} 3 {} {}",
                            zone.name.as_str(),
                            key.role.flags(),
                            key.algorithm.to_int(),
                            key.public_key
                        ),
                        private_key: key.private_key.clone(),
                    })
                    .collect(),
            })
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to export DNSSEC keys").await
    }

    /// Import one BIND key pair as an active key and re-sign the zone: the
    /// migration path for a zone already signed elsewhere.
    pub async fn import_key(
        caller: &Caller,
        zone_name: &str,
        request: ImportDnssecKeyRequest,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        let role_override = request
            .role
            .as_deref()
            .map(str::parse::<DnssecKeyRole>)
            .transpose()
            .map_err(ServiceError::invalid_input)?;

        let mut tx = RepositoryService::begin_tx("failed to import DNSSEC key").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

            let key = import_key(
                &zone,
                role_override,
                &request.dnskey,
                &request.private_key,
                Utc::now(),
            )
            .map_err(ServiceError::invalid_input)?;
            if keys
                .iter()
                .any(|other| other.key_tag == key.key_tag && other.algorithm == key.algorithm)
            {
                return Err(ServiceError::invalid_input(format!(
                    "key tag {} ({}) is already present in zone {}",
                    key.key_tag,
                    key.algorithm,
                    zone.name.as_str()
                )));
            }

            let mut keys = keys;
            keys.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);

            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = Self::earliest_expiry_tx(&mut tx, zone.id).await?;
            let withdrawing = RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some();
            build_status(
                &zone,
                zone.dnssec_denial,
                &keys,
                earliest,
                new_serial,
                withdrawing,
            )
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to import DNSSEC key").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }
}
