//! Zone grants for TSIG keys: name/type scopes for updates, whole-zone grants
//! for transfers, and optional read-only access.

use std::collections::HashMap;

use bindizr_core::{
    dns::name::{OwnerName, ZoneName},
    model::{tsig_grant::TsigGrantId, tsig_key::TsigKeyId, zone::ZoneId},
};
use bindizr_db::LockLevel;
use chrono::Utc;

use crate::{
    Context, Transaction,
    authorization::Caller,
    db,
    error::ServiceError,
    grant_pattern::{normalize_pattern, normalize_types},
    model::{
        record::RecordType,
        tsig_grant::{TsigGrant, TsigGrantWithNames},
        tsig_key::TsigKey,
        zone::Zone,
    },
    types::{GetTsigGrantResponse, PageFilter, PaginatedResponse, build_page},
    zone,
};

/// Grant `key_name` rights in `zone_name`, optionally restricted to a
/// record name pattern and/or record types, and to transfers alone. Global
/// keys are rejected: they already cover every zone and never carry grants.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    key_name: &str,
    zone_name: &ZoneName,
    record_name_pattern: Option<&str>,
    record_types: Option<&str>,
    can_write: bool,
) -> Result<TsigGrantWithNames, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let key = super::lookup_by_name(cx, key_name).await?;
    if key.is_global {
        return Err(ServiceError::invalid_input(format!(
            "TSIG key '{}' is global and already covers every zone; it cannot be granted one",
            key.name
        )));
    }
    let zone = zone::lookup_by_name(cx, zone_name).await?;

    let record_name_pattern = normalize_pattern(record_name_pattern)?;
    let record_types = normalize_types(record_types)?;

    let grant = db::tsig_grant::create(
        cx.db(),
        TsigGrant {
            id: TsigGrantId::UNWRITTEN,
            zone_id: zone.id,
            tsig_key_id: key.id,
            record_name_pattern,
            record_types,
            can_write,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        // The zone or key can go between the lookups above and this insert;
        // the FK reports it.
        if e.is_foreign_key_violation() {
            ServiceError::ZoneNotFound("Zone or TSIG key no longer exists".to_string())
        } else {
            e.into()
        }
    })?;

    Ok(TsigGrantWithNames {
        grant,
        tsig_key_name: key.name,
        zone_name: zone.name.to_string(),
    })
}

/// Every grant of `key_name`, with the zone each covers.
pub async fn list_by_key(
    cx: &Context,
    caller: &Caller,
    key_name: &str,
    page: PageFilter,
) -> Result<PaginatedResponse<GetTsigGrantResponse>, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let key = super::lookup_by_name(cx, key_name).await?;
    let grants = db::tsig_grant::list_by_key_id(cx.db(), key.id).await?;

    let zone_names: HashMap<ZoneId, String> = db::zone::list_all(cx.db())
        .await?
        .into_iter()
        .map(|zone| (zone.id, zone.name.to_string()))
        .collect();

    build_page(
        grants
            .into_iter()
            .map(|grant| {
                GetTsigGrantResponse::from(&TsigGrantWithNames {
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
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    page: PageFilter,
) -> Result<PaginatedResponse<GetTsigGrantResponse>, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let zone = zone::lookup_by_name(cx, zone_name).await?;
    let grants = db::tsig_grant::list_by_zone_id(cx.db(), zone.id).await?;

    let key_names: HashMap<TsigKeyId, String> = db::tsig_key::list_all(cx.db())
        .await?
        .into_iter()
        .map(|key| (key.id, key.name))
        .collect();

    build_page(
        grants
            .into_iter()
            .map(|grant| {
                GetTsigGrantResponse::from(&TsigGrantWithNames {
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
    tx: &mut Transaction<'_>,
    zone: &Zone,
    key: &TsigKey,
) -> Result<bool, ServiceError> {
    if key.is_global {
        return Ok(true);
    }
    let grants =
        db::tsig_grant::list_by_zone_id_and_key_id_tx(tx, zone.id, key.id, LockLevel::Shared)
            .await?;
    Ok(has_whole_zone_grant(&grants))
}

/// Revoke one of `key_name`'s grants by id. An id that belongs to another
/// key reads as not found.
pub async fn revoke(
    cx: &Context,
    caller: &Caller,
    key_name: &str,
    grant_id: TsigGrantId,
) -> Result<(), ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let key = super::lookup_by_name(cx, key_name).await?;
    let grant = db::tsig_grant::get(cx.db(), grant_id)
        .await?
        .filter(|grant| grant.tsig_key_id == key.id)
        .ok_or_else(|| ServiceError::tsig_grant_not_found(grant_id))?;

    Ok(db::tsig_grant::delete(cx.db(), grant.id).await?)
}

/// Revoke every grant `key_name` holds in `zone_name`, returning how many
/// went. Matching none is not an error: the rights already read the way
/// the request asked for.
pub async fn revoke_by_key_and_zone(
    cx: &Context,
    caller: &Caller,
    key_name: &str,
    zone_name: &ZoneName,
) -> Result<u64, ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let key = super::lookup_by_name(cx, key_name).await?;
    let zone = zone::lookup_by_name(cx, zone_name).await?;

    Ok(db::tsig_grant::delete_by_key_id_and_zone_id(cx.db(), key.id, zone.id).await?)
}

/// Revoke a grant by its id, which identifies the row on its own.
pub async fn revoke_by_id(
    cx: &Context,
    caller: &Caller,
    grant_id: TsigGrantId,
) -> Result<(), ServiceError> {
    caller.authorize_global("manage TSIG keys and grants")?;

    let grant = db::tsig_grant::get(cx.db(), grant_id)
        .await?
        .ok_or_else(|| ServiceError::tsig_grant_not_found(grant_id))?;

    Ok(db::tsig_grant::delete(cx.db(), grant.id).await?)
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
        .any(|grant| grant.can_write && grant.matches(relative_name, record_type))
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
        .any(|grant| grant.matches(relative_name, record_type))
}

/// Whether any grant covers the zone whole. A transfer hands the zone over
/// whole, so a grant narrowed to part of it authorizes none.
fn has_whole_zone_grant(grants: &[TsigGrant]) -> bool {
    grants.iter().any(TsigGrant::is_unrestricted)
}

#[cfg(test)]
mod tests;
