//! Record-plane grants for API tokens, the HTTP twin of
//! [`crate::tsig_key::grant`]. A grant belongs to its token and names the
//! zone it covers.

use std::collections::HashMap;

use bindizr_db::zone::ZoneFilter;
use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    db,
    error::ServiceError,
    grant_pattern::{normalize_pattern, normalize_types},
    model::{
        api_token::ApiToken,
        token_grant::{TokenGrant, TokenGrantWithNames},
    },
    types::{GetTokenGrantResponse, PageFilter, PaginatedResponse},
    zone,
};

/// Grant `token_name` record rights in `zone_name`, optionally restricted
/// to a record name pattern and/or record types. Global tokens are
/// rejected: they already cover every zone and never carry grants.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    token_name: &str,
    zone_name: &str,
    record_name_pattern: Option<&str>,
    record_types: Option<&str>,
    can_write: bool,
) -> Result<TokenGrantWithNames, ServiceError> {
    caller.authorize_global("manage token grants")?;

    let token = super::lookup_by_name(cx, token_name).await?;
    if token.is_global {
        return Err(ServiceError::invalid_input(format!(
            "API token '{}' is global and already covers every zone; it cannot be granted one",
            token.name
        )));
    }
    let zone = zone::lookup_by_name(cx, zone_name).await?;

    let record_name_pattern = normalize_pattern(record_name_pattern)?;
    let record_types = normalize_types(record_types)?;

    let grant = db::token_grant::create(
        cx.db(),
        TokenGrant {
            id: 0,
            zone_id: zone.id,
            api_token_id: token.id,
            record_name_pattern,
            record_types,
            can_write,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        // The zone or token can go between the lookups above and this insert;
        // the FK reports it.
        if e.is_foreign_key_violation() {
            ServiceError::ZoneNotFound("Zone or token no longer exists".to_string())
        } else {
            e.into()
        }
    })?;

    Ok(TokenGrantWithNames {
        grant,
        api_token_name: token.name,
        zone_name: zone.name.to_string(),
    })
}

/// Every grant of `token_name`, with the zone each covers.
pub async fn list_by_token(
    cx: &Context,
    caller: &Caller,
    token_name: &str,
    page: PageFilter,
) -> Result<PaginatedResponse<GetTokenGrantResponse>, ServiceError> {
    caller.authorize_global("manage token grants")?;

    let token = super::lookup_by_name(cx, token_name).await?;
    list_self(cx, &token, page).await
}

/// Every grant of `token`, with the zone each covers. Any token may read
/// its own, so there is no caller to gate.
pub async fn list_self(
    cx: &Context,
    token: &ApiToken,
    page: PageFilter,
) -> Result<PaginatedResponse<GetTokenGrantResponse>, ServiceError> {
    let grants = db::token_grant::list_by_token_id(cx.db(), token.id).await?;

    // Any token reaches this, so read only its granted zones.
    let zone_names: HashMap<i32, String> = db::zone::list_by_filter(
        cx.db(),
        ZoneFilter {
            scope_token_id: Some(token.id),
            ..ZoneFilter::default()
        },
    )
    .await?
    .into_iter()
    .map(|zone| (zone.id, zone.name.to_string()))
    .collect();

    PaginatedResponse::from_collection(
        grants
            .into_iter()
            .map(|grant| {
                GetTokenGrantResponse::from_grant(&TokenGrantWithNames {
                    zone_name: zone_names.get(&grant.zone_id).cloned().unwrap_or_default(),
                    api_token_name: token.name.clone(),
                    grant,
                })
            })
            .collect(),
        page.limit,
        page.offset,
    )
}

/// Every grant that applies to `zone_name`, with the token each belongs to.
pub async fn list_by_zone(
    cx: &Context,
    caller: &Caller,
    zone_name: &str,
    page: PageFilter,
) -> Result<PaginatedResponse<GetTokenGrantResponse>, ServiceError> {
    caller.authorize_global("manage token grants")?;

    let zone = zone::lookup_by_name(cx, zone_name).await?;
    let grants = db::token_grant::list_by_zone_id(cx.db(), zone.id).await?;

    let token_names: HashMap<i32, String> = db::api_token::list_all(cx.db())
        .await?
        .into_iter()
        .map(|token| (token.id, token.name))
        .collect();

    PaginatedResponse::from_collection(
        grants
            .into_iter()
            .map(|grant| {
                GetTokenGrantResponse::from_grant(&TokenGrantWithNames {
                    api_token_name: token_names
                        .get(&grant.api_token_id)
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

/// Revoke one of `token_name`'s grants by id. An id that belongs to another
/// token reads as not found.
pub async fn revoke(
    cx: &Context,
    caller: &Caller,
    token_name: &str,
    grant_id: i32,
) -> Result<(), ServiceError> {
    caller.authorize_global("manage token grants")?;

    let token = super::lookup_by_name(cx, token_name).await?;
    let grant = db::token_grant::get(cx.db(), grant_id)
        .await?
        .filter(|grant| grant.api_token_id == token.id)
        .ok_or_else(|| ServiceError::token_grant_not_found(grant_id))?;

    Ok(db::token_grant::delete(cx.db(), grant.id).await?)
}

/// Revoke every grant `token_name` holds in `zone_name`, returning how
/// many went. Matching none is not an error: the rights already read the
/// way the request asked for.
pub async fn revoke_by_token_and_zone(
    cx: &Context,
    caller: &Caller,
    token_name: &str,
    zone_name: &str,
) -> Result<u64, ServiceError> {
    caller.authorize_global("manage token grants")?;

    let token = super::lookup_by_name(cx, token_name).await?;
    let zone = zone::lookup_by_name(cx, zone_name).await?;

    Ok(db::token_grant::delete_by_token_id_and_zone_id(cx.db(), token.id, zone.id).await?)
}

/// Revoke a grant by its id, which identifies the row on its own.
pub async fn revoke_by_id(
    cx: &Context,
    caller: &Caller,
    grant_id: i32,
) -> Result<(), ServiceError> {
    caller.authorize_global("manage token grants")?;

    let grant = db::token_grant::get(cx.db(), grant_id)
        .await?
        .ok_or_else(|| ServiceError::token_grant_not_found(grant_id))?;

    Ok(db::token_grant::delete(cx.db(), grant.id).await?)
}
