//! nsupdate grants for TSIG keys, in the spirit of BIND's `update-policy`.
//! A grant belongs to its key and names the zone it covers.

use std::collections::HashMap;

use bindizr_core::dns::name::OwnerName;
use chrono::Utc;

use super::TsigKeyService;
use crate::{
    authorization::Caller,
    error::ServiceError,
    grant_pattern::{normalize_pattern, normalize_types, pattern_matches_name, types_match},
    model::{
        record::RecordType,
        tsig_grant::{TsigGrant, TsigGrantWithNames},
    },
    repository::RepositoryService,
    zone::ZoneService,
};

/// Grants and revokes zone nsupdate rights for TSIG keys.
pub struct TsigGrantService;

impl TsigGrantService {
    /// Grant `key_name` nsupdate rights in `zone_name`, optionally restricted
    /// to a record name pattern and/or record types. Global keys are rejected:
    /// they already cover every zone and never carry grants.
    pub async fn grant(
        caller: &Caller,
        key_name: &str,
        zone_name: &str,
        record_name_pattern: Option<&str>,
        record_types: Option<&str>,
    ) -> Result<TsigGrantWithNames, ServiceError> {
        caller.require_global("manage TSIG keys and grants")?;

        let key = TsigKeyService::lookup_by_name(key_name).await?;
        if key.is_global {
            return Err(ServiceError::invalid_input(format!(
                "TSIG key '{}' is global and already covers every zone; it cannot be granted one",
                key.name
            )));
        }
        let zone = ZoneService::lookup_by_name(zone_name).await?;

        let record_name_pattern = normalize_pattern(record_name_pattern)?;
        let record_types = normalize_types(record_types)?;

        let grant = RepositoryService::create_tsig_grant(TsigGrant {
            id: 0,
            zone_id: zone.id,
            tsig_key_id: key.id,
            record_name_pattern,
            record_types,
            created_at: Utc::now(),
        })
        .await?;

        Ok(TsigGrantWithNames {
            grant,
            tsig_key_name: key.name,
            zone_name: zone.name.to_string(),
        })
    }

    /// Every grant of `key_name`, with the zone each covers.
    pub async fn list_by_key(
        caller: &Caller,
        key_name: &str,
    ) -> Result<Vec<TsigGrantWithNames>, ServiceError> {
        caller.require_global("manage TSIG keys and grants")?;

        let key = TsigKeyService::lookup_by_name(key_name).await?;
        let grants = RepositoryService::list_tsig_grants_by_key_id(key.id).await?;

        let zone_names: HashMap<i32, String> = RepositoryService::list_zones()
            .await?
            .into_iter()
            .map(|zone| (zone.id, zone.name.to_string()))
            .collect();

        Ok(grants
            .into_iter()
            .map(|grant| TsigGrantWithNames {
                zone_name: zone_names.get(&grant.zone_id).cloned().unwrap_or_default(),
                tsig_key_name: key.name.clone(),
                grant,
            })
            .collect())
    }

    /// Every grant that applies to `zone_name`, with the key each belongs to.
    pub async fn list_by_zone(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<Vec<TsigGrantWithNames>, ServiceError> {
        caller.require_global("manage TSIG keys and grants")?;

        let zone = ZoneService::lookup_by_name(zone_name).await?;
        let grants = RepositoryService::list_tsig_grants_by_zone_id(zone.id).await?;

        let key_names: HashMap<i32, String> = RepositoryService::list_tsig_keys()
            .await?
            .into_iter()
            .map(|key| (key.id, key.name))
            .collect();

        Ok(grants
            .into_iter()
            .map(|grant| TsigGrantWithNames {
                tsig_key_name: key_names
                    .get(&grant.tsig_key_id)
                    .cloned()
                    .unwrap_or_default(),
                zone_name: zone.name.to_string(),
                grant,
            })
            .collect())
    }

    /// Revoke one of `key_name`'s grants by id. An id that belongs to another
    /// key reads as not found.
    pub async fn revoke(
        caller: &Caller,
        key_name: &str,
        grant_id: i32,
    ) -> Result<(), ServiceError> {
        caller.require_global("manage TSIG keys and grants")?;

        let key = TsigKeyService::lookup_by_name(key_name).await?;
        let grant = RepositoryService::get_tsig_grant(grant_id)
            .await?
            .filter(|grant| grant.tsig_key_id == key.id)
            .ok_or_else(|| ServiceError::tsig_grant_not_found(grant_id))?;

        RepositoryService::delete_tsig_grant(grant.id).await
    }
}

/// Whether any grant authorizes an update of `record_type` at the relative
/// owner name. `record_type` is `None` for whole-name deletes (wire TYPE ANY),
/// which only a grant with unrestricted types may authorize.
pub(crate) fn authorize_update(
    grants: &[TsigGrant],
    relative_name: &OwnerName,
    record_type: Option<&RecordType>,
) -> bool {
    grants.iter().any(|grant| {
        pattern_matches_name(&grant.record_name_pattern, relative_name)
            && types_match(&grant.record_types, record_type)
    })
}

#[cfg(test)]
mod tests;
