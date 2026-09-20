//! Zone grants for TSIG keys: name/type scopes for updates, whole-zone grants
//! for transfers, and optional read-only access.

use std::collections::HashMap;

use bindizr_core::dns::name::OwnerName;
use bindizr_db::repository::LockLevel;
use chrono::Utc;

use super::TsigKeyService;
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    grant_pattern::{MATCH_ANY, matches_name, matches_types, normalize_pattern, normalize_types},
    model::{
        record::RecordType,
        tsig_grant::{TsigGrant, TsigGrantWithNames},
        tsig_key::TsigKey,
        zone::Zone,
    },
    repository::RepositoryService,
    types::{GetTsigGrantResponse, PageFilter, PaginatedResponse},
    zone::ZoneService,
};

/// Grants and revokes update and transfer rights for TSIG keys.
pub struct TsigGrantService;

impl TsigGrantService {
    /// Grant `key_name` rights in `zone_name`, optionally restricted to a
    /// record name pattern and/or record types, and to transfers alone. Global
    /// keys are rejected: they already cover every zone and never carry grants.
    pub async fn grant(
        caller: &Caller,
        key_name: &str,
        zone_name: &str,
        record_name_pattern: Option<&str>,
        record_types: Option<&str>,
        can_write: bool,
    ) -> Result<TsigGrantWithNames, ServiceError> {
        caller.authorize_global("manage TSIG keys and grants")?;

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
            can_write,
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
        page: PageFilter,
    ) -> Result<PaginatedResponse<GetTsigGrantResponse>, ServiceError> {
        caller.authorize_global("manage TSIG keys and grants")?;

        let key = TsigKeyService::lookup_by_name(key_name).await?;
        let grants = RepositoryService::list_tsig_grants_by_key_id(key.id).await?;

        let zone_names: HashMap<i32, String> = RepositoryService::list_zones()
            .await?
            .into_iter()
            .map(|zone| (zone.id, zone.name.to_string()))
            .collect();

        PaginatedResponse::from_collection(
            grants
                .into_iter()
                .map(|grant| {
                    GetTsigGrantResponse::from_grant(&TsigGrantWithNames {
                        zone_name: zone_names.get(&grant.zone_id).cloned().unwrap_or_default(),
                        tsig_key_name: key.name.clone(),
                        grant,
                    })
                })
                .collect(),
            page.limit,
            page.offset,
        )
    }

    /// Every grant that applies to `zone_name`, with the key each belongs to.
    pub async fn list_by_zone(
        caller: &Caller,
        zone_name: &str,
        page: PageFilter,
    ) -> Result<PaginatedResponse<GetTsigGrantResponse>, ServiceError> {
        caller.authorize_global("manage TSIG keys and grants")?;

        let zone = ZoneService::lookup_by_name(zone_name).await?;
        let grants = RepositoryService::list_tsig_grants_by_zone_id(zone.id).await?;

        let key_names: HashMap<i32, String> = RepositoryService::list_tsig_keys()
            .await?
            .into_iter()
            .map(|key| (key.id, key.name))
            .collect();

        PaginatedResponse::from_collection(
            grants
                .into_iter()
                .map(|grant| {
                    GetTsigGrantResponse::from_grant(&TsigGrantWithNames {
                        tsig_key_name: key_names
                            .get(&grant.tsig_key_id)
                            .cloned()
                            .unwrap_or_default(),
                        zone_name: zone.name.to_string(),
                        grant,
                    })
                })
                .collect(),
            page.limit,
            page.offset,
        )
    }

    /// Whether `key` may transfer `zone`: a global key covers every zone, a
    /// scoped one needs a grant over the whole zone, read-only or not. The
    /// grants are share-locked so a revocation waits for the read they gate.
    pub(crate) async fn authorize_whole_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        key: &TsigKey,
    ) -> Result<bool, ServiceError> {
        if key.is_global {
            return Ok(true);
        }
        let grants = RepositoryService::list_tsig_grants_by_zone_id_and_key_id_tx(
            tx,
            zone.id,
            key.id,
            LockLevel::Shared,
        )
        .await?;
        Ok(covers_whole_zone(&grants))
    }

    /// Revoke one of `key_name`'s grants by id. An id that belongs to another
    /// key reads as not found.
    pub async fn revoke(
        caller: &Caller,
        key_name: &str,
        grant_id: i32,
    ) -> Result<(), ServiceError> {
        caller.authorize_global("manage TSIG keys and grants")?;

        let key = TsigKeyService::lookup_by_name(key_name).await?;
        let grant = RepositoryService::get_tsig_grant(grant_id)
            .await?
            .filter(|grant| grant.tsig_key_id == key.id)
            .ok_or_else(|| ServiceError::tsig_grant_not_found(grant_id))?;

        RepositoryService::delete_tsig_grant(grant.id).await
    }

    /// Revoke every grant `key_name` holds in `zone_name`, returning how many
    /// went. Matching none is not an error: the rights already read the way
    /// the request asked for.
    pub async fn revoke_by_key_and_zone(
        caller: &Caller,
        key_name: &str,
        zone_name: &str,
    ) -> Result<u64, ServiceError> {
        caller.authorize_global("manage TSIG keys and grants")?;

        let key = TsigKeyService::lookup_by_name(key_name).await?;
        let zone = ZoneService::lookup_by_name(zone_name).await?;

        RepositoryService::delete_tsig_grants_by_key_id_and_zone_id(key.id, zone.id).await
    }

    /// Revoke a grant by its id, which identifies the row on its own.
    pub async fn revoke_by_id(caller: &Caller, grant_id: i32) -> Result<(), ServiceError> {
        caller.authorize_global("manage TSIG keys and grants")?;

        let grant = RepositoryService::get_tsig_grant(grant_id)
            .await?
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
    grants
        .iter()
        .any(|grant| grant.can_write && matches_grant(grant, relative_name, record_type))
}

/// Whether any grant reaches the records a prerequisite names: a read, so a
/// read-only grant suffices; a whole-name one (`None`) needs unrestricted types.
pub(crate) fn authorize_prerequisite(
    grants: &[TsigGrant],
    relative_name: &OwnerName,
    record_type: Option<&RecordType>,
) -> bool {
    grants
        .iter()
        .any(|grant| matches_grant(grant, relative_name, record_type))
}

/// Whether one grant's name pattern and type list cover `record_type` at the
/// relative owner name.
fn matches_grant(
    grant: &TsigGrant,
    relative_name: &OwnerName,
    record_type: Option<&RecordType>,
) -> bool {
    matches_name(&grant.record_name_pattern, relative_name)
        && matches_types(&grant.record_types, record_type)
}

/// Whether any grant covers the zone whole. A transfer hands the zone over
/// whole, so a grant narrowed to part of it authorizes none.
fn covers_whole_zone(grants: &[TsigGrant]) -> bool {
    grants
        .iter()
        .any(|grant| grant.record_name_pattern == MATCH_ANY && grant.record_types == MATCH_ANY)
}

#[cfg(test)]
mod tests;
