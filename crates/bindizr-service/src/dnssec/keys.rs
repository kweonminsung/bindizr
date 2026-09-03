//! Importing and exporting raw key material in BIND key-file form. Reached
//! only over the daemon socket: private keys never transit the HTTP API.

use bindizr_core::dns::dnssec::import_key;
use chrono::Utc;

use super::{DnssecService, notify_zone, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dnssec_policy::normalize_policy_name,
    error::ServiceError,
    model::{dnssec_key::DnssecKeyRole, dnssec_policy::DEFAULT_DNSSEC_POLICY_NAME, zone::Zone},
    repository::RepositoryService,
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

        // One locked transaction: a rename cannot split the rendered name
        // from the keys.
        let mut tx = RepositoryService::begin_read_tx("failed to export DNSSEC keys").await?;
        let result = async {
            let (zone, _, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
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
    /// migration path for a zone already signed elsewhere. An unsigned zone
    /// takes `request.policy` (the built-in `default` when omitted); a zone
    /// that already signs keeps its policy.
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
        let requested_policy = request
            .policy
            .as_deref()
            .map(normalize_policy_name)
            .transpose()?;

        let mut tx = RepositoryService::begin_tx("failed to import DNSSEC key").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;

            let (zone, policy) = match Self::find_zone_policy_tx(&mut tx, &zone).await? {
                Some(policy) => {
                    if requested_policy
                        .as_deref()
                        .is_some_and(|name| name != policy.name)
                    {
                        return Err(ServiceError::invalid_input(format!(
                            "zone '{}' already signs under policy '{}'; change it with \
                             set-policy rather than on import",
                            zone.name.as_str(),
                            policy.name
                        )));
                    }
                    (zone, policy)
                }
                None => {
                    let name = requested_policy
                        .as_deref()
                        .unwrap_or(DEFAULT_DNSSEC_POLICY_NAME);
                    let policy = RepositoryService::get_dnssec_policy_by_name_tx(
                        &mut tx,
                        name,
                        LockLevel::Shared,
                    )
                    .await?
                    .ok_or_else(|| ServiceError::dnssec_policy_not_found(name))?;
                    RepositoryService::update_zone_dnssec_policy_id_tx(
                        &mut tx,
                        zone.id,
                        Some(policy.id),
                    )
                    .await?;
                    (
                        Zone {
                            dnssec_policy_id: Some(policy.id),
                            ..zone
                        },
                        policy,
                    )
                }
            };

            let key = import_key(
                &zone,
                role_override,
                &request.dnskey,
                &request.private_key,
                Utc::now(),
            )
            .map_err(ServiceError::invalid_input)?;
            // The policy names the algorithm the zone advertises; a second
            // algorithm may only join through an algorithm rollover, whose
            // keys are already in the set.
            if key.algorithm != policy.algorithm
                && !keys.iter().any(|other| other.algorithm == key.algorithm)
            {
                return Err(ServiceError::invalid_input(format!(
                    "key algorithm {} does not match policy '{}' ({}); import it under a \
                     policy of that algorithm",
                    key.algorithm, policy.name, policy.algorithm
                )));
            }
            // Distinct keys may share a tag (RFC 4034, Appendix B); only a
            // byte-identical public key is a duplicate.
            if keys
                .iter()
                .any(|other| other.algorithm == key.algorithm && other.public_key == key.public_key)
            {
                return Err(ServiceError::invalid_input(format!(
                    "this key (tag {}, {}) is already present in zone {}",
                    key.key_tag,
                    key.algorithm,
                    zone.name.as_str()
                )));
            }

            let mut keys = keys;
            keys.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);

            // A split pair arrives one key at a time: signing waits until
            // the set carries both a key-RRset signer and a data signer.
            let signable = keys.iter().any(|key| key.signs_key_rrsets())
                && keys.iter().any(|key| key.signs_zone_data(&keys));
            let serial = if signable {
                Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                    .await?
                    .unwrap_or(zone.serial)
            } else {
                zone.serial
            };

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, serial)
                .await
                .map(|status| (status, signable))
        }
        .await;
        let (response, signed) =
            RepositoryService::finish_tx(tx, result, "failed to import DNSSEC key").await?;

        if signed {
            notify_zone(&response.zone_name).await;
        }
        Ok(response)
    }
}
