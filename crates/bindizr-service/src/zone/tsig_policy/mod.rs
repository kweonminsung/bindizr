use std::collections::HashMap;

use chrono::Utc;

use super::ZoneService;
use crate::{
    RepositoryTx,
    error::ServiceError,
    model::{record::RecordType, zone_tsig_policy::ZoneTsigPolicy},
    policy_pattern::{normalize_pattern, normalize_types, pattern_matches_name, types_match},
    repository::RepositoryService,
    tsig_key::TsigKeyService,
};

/// A zone TSIG policy joined with the name of the key it grants.
#[derive(Debug, Clone)]
pub struct ZoneTsigPolicyWithKey {
    pub policy: ZoneTsigPolicy,
    pub tsig_key_name: String,
}

/// Grants and revokes per-zone nsupdate rights for TSIG keys.
pub struct ZoneTsigPolicyService;

impl ZoneTsigPolicyService {
    /// Grant `key_name` nsupdate rights in `zone_name`, optionally restricted
    /// to a record name pattern and/or record types. Global keys are rejected:
    /// they already cover every zone and never carry policies.
    pub async fn add(
        zone_name: &str,
        key_name: &str,
        record_name_pattern: Option<&str>,
        record_types: Option<&str>,
    ) -> Result<ZoneTsigPolicyWithKey, ServiceError> {
        let zone = ZoneService::get_by_name(zone_name).await?;
        let key = TsigKeyService::get(key_name).await?;

        if key.is_global {
            return Err(ServiceError::invalid_input(format!(
                "TSIG key '{}' is global and already covers every zone; policies cannot be added to it",
                key.name
            )));
        }

        let record_name_pattern = normalize_pattern(record_name_pattern)?;
        let record_types = normalize_types(record_types)?;

        let policy = RepositoryService::create_zone_tsig_policy(ZoneTsigPolicy {
            id: 0,
            zone_id: zone.id,
            tsig_key_id: key.id,
            record_name_pattern,
            record_types,
            created_at: Utc::now(),
        })
        .await?;

        Ok(ZoneTsigPolicyWithKey {
            policy,
            tsig_key_name: key.name,
        })
    }

    /// List all TSIG policies of a zone with their key names.
    pub async fn list(zone_name: &str) -> Result<Vec<ZoneTsigPolicyWithKey>, ServiceError> {
        let zone = ZoneService::get_by_name(zone_name).await?;
        let policies = RepositoryService::get_zone_tsig_policies_by_zone_id(zone.id).await?;

        let key_names: HashMap<i32, String> = RepositoryService::get_all_tsig_keys()
            .await?
            .into_iter()
            .map(|key| (key.id, key.name))
            .collect();

        Ok(policies
            .into_iter()
            .map(|policy| ZoneTsigPolicyWithKey {
                tsig_key_name: key_names
                    .get(&policy.tsig_key_id)
                    .cloned()
                    .unwrap_or_default(),
                policy,
            })
            .collect())
    }

    /// Remove one policy of a zone by policy id.
    pub async fn remove(zone_name: &str, policy_id: i32) -> Result<(), ServiceError> {
        let zone = ZoneService::get_by_name(zone_name).await?;

        let policy = RepositoryService::get_zone_tsig_policy_by_id(policy_id)
            .await?
            .filter(|policy| policy.zone_id == zone.id)
            .ok_or_else(|| ServiceError::tsig_policy_not_found(policy_id))?;

        RepositoryService::delete_zone_tsig_policy(policy.id).await
    }

    /// Policies granting `tsig_key_id` rights in `zone_id`, within the caller's
    /// transaction. Used by the nsupdate path.
    pub async fn get_by_zone_and_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
    ) -> Result<Vec<ZoneTsigPolicy>, ServiceError> {
        RepositoryService::get_zone_tsig_policies_by_zone_and_key_tx(tx, zone_id, tsig_key_id).await
    }
}

/// Whether any policy authorizes an update of `record_type` at the relative
/// owner name. `record_type` is `None` for whole-name deletes (wire TYPE ANY),
/// which only a policy with unrestricted types may authorize.
pub fn authorize_update(
    policies: &[ZoneTsigPolicy],
    relative_name: &str,
    record_type: Option<&RecordType>,
) -> bool {
    policies.iter().any(|policy| {
        pattern_matches_name(&policy.record_name_pattern, relative_name)
            && types_match(&policy.record_types, record_type)
    })
}

#[cfg(test)]
mod tests;
