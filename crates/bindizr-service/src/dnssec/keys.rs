//! Importing and exporting raw key material in BIND key-file form. Reached
//! only over the daemon socket: private keys never transit the HTTP API.

use bindizr_core::dns::dnssec::{import_key, to_bind_private_file};
use chrono::Utc;

use super::{DnssecService, notify_zone, status::build_status_tx, to_key_layout};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dnssec_policy::normalize_policy_name,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DEFAULT_DNSSEC_POLICY_NAME,
        zone::Zone,
    },
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
                        private_key: to_bind_private_file(key),
                    })
                    .collect(),
            })
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to export DNSSEC keys").await
    }

    /// Import an unsigned zone's complete key set from BIND key pairs and
    /// sign it: one CSK pair, or a KSK pair and a ZSK pair under a split-key
    /// policy. The migration path for a zone signed elsewhere.
    pub async fn import_keys(
        caller: &Caller,
        zone_name: &str,
        request: ImportDnssecKeyRequest,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        if request.keys.is_empty() {
            return Err(ServiceError::invalid_input("no key pair to import"));
        }
        let policy_name = normalize_policy_name(
            request
                .policy
                .as_deref()
                .unwrap_or(DEFAULT_DNSSEC_POLICY_NAME),
        )?;

        let mut tx = RepositoryService::begin_tx("failed to import DNSSEC keys").await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if !RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None)
                .await?
                .is_empty()
            {
                return Err(ServiceError::dnssec_already_enabled(zone.name.as_str()));
            }
            let policy = RepositoryService::get_dnssec_policy_by_name_tx(
                &mut tx,
                &policy_name,
                LockLevel::Shared,
            )
            .await?
            .ok_or_else(|| ServiceError::dnssec_policy_not_found(&policy_name))?;

            let now = Utc::now();
            let mut keys: Vec<DnssecKey> = Vec::with_capacity(request.keys.len());
            for pair in &request.keys {
                let key = import_key(
                    &zone,
                    policy.split_keys,
                    &pair.dnskey,
                    &pair.private_key,
                    now,
                )
                .map_err(ServiceError::invalid_input)?;
                if key.algorithm != policy.algorithm {
                    return Err(ServiceError::invalid_input(format!(
                        "key algorithm {} does not match policy '{}' ({}); import it under a \
                         policy of that algorithm",
                        key.algorithm, policy.name, policy.algorithm
                    )));
                }
                // Distinct keys may share a tag (RFC 4034, Appendix B); only
                // a byte-identical public key is a duplicate.
                if keys.iter().any(|other| other.public_key == key.public_key) {
                    return Err(ServiceError::invalid_input(format!(
                        "key tag {} is given twice",
                        key.key_tag
                    )));
                }
                keys.push(key);
            }
            // The timing placed each key in its rollover; every role the
            // layout names still needs the active key that signs for it.
            let has_active = |role: DnssecKeyRole| {
                keys.iter()
                    .any(|key| key.role == role && key.state == DnssecKeyState::Active)
            };
            let signed = if policy.split_keys {
                has_active(DnssecKeyRole::Ksk) && has_active(DnssecKeyRole::Zsk)
            } else {
                has_active(DnssecKeyRole::Csk)
            };
            if !signed {
                return Err(ServiceError::invalid_input(format!(
                    "key set does not match policy '{}' ({}); import an active pair for \
                     every role it names, together with any published or retired pairs the \
                     rollover still holds",
                    policy.name,
                    to_key_layout(policy.split_keys)
                )));
            }

            RepositoryService::update_zone_dnssec_policy_id_tx(&mut tx, zone.id, Some(policy.id))
                .await?;
            let zone = Zone {
                dnssec_policy_id: Some(policy.id),
                ..zone
            };
            let mut stored = Vec::with_capacity(keys.len());
            for key in keys {
                stored.push(RepositoryService::create_dnssec_key_tx(&mut tx, key).await?);
            }

            let new_serial = Self::resign_zone_tx(
                &mut tx,
                &zone,
                &policy,
                &stored,
                false,
                &caller.change_subject(),
            )
            .await?
            .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &stored, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to import DNSSEC keys").await?;

        crate::log_info!("event=dnssec_import_keys zone={}", response.zone_name);
        notify_zone(&response.zone_name).await;
        Ok(response)
    }
}
