//! A role's grants: actions in one zone or all zones.

use std::collections::HashMap;

use bindizr_core::{
    dns::name::ZoneName,
    model::{
        api_token::ApiToken,
        grant_pattern::MATCH_ANY,
        role::Role,
        role_grant::{Action, ActionSet, RoleGrant, RoleGrantId, RoleZoneScope},
        zone::ZoneId,
    },
};
use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    grant_pattern::{normalize_pattern, normalize_types},
    pagination::build_page,
    transaction,
    types::{CreateRoleGrantRequest, GetRoleGrantResponse, PageRequest, PaginatedResponse},
    zone,
};

/// Grant `role_name` the request's actions in its zone, or in all zones
/// when it names none.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    role_name: &str,
    request: &CreateRoleGrantRequest,
) -> Result<GetRoleGrantResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = super::lookup_by_name(cx, role_name).await?;
    super::refuse_builtin(&role)?;

    let actions = request
        .actions
        .iter()
        .map(|action| action.trim().parse::<Action>())
        .collect::<Result<ActionSet, _>>()
        .map_err(ServiceError::invalid_input)?;
    if actions.is_empty() {
        return Err(ServiceError::invalid_input(
            "a grant needs at least one action",
        ));
    }
    let record_name_pattern = normalize_pattern(request.record_name_pattern.as_deref())?;
    let record_types = normalize_types(request.record_types.as_deref())?;
    let constrained = record_name_pattern != MATCH_ANY || record_types != MATCH_ANY;
    if constrained && !actions.iter().any(Action::is_record_action) {
        return Err(ServiceError::invalid_input(
            "record_name_pattern and record_types constrain record actions, and the grant has none",
        ));
    }

    let zone = match request.zone_name.as_deref() {
        None => None,
        Some(zone_name) => {
            if let Some(action) = actions.iter().find(|action| action.needs_all_zones()) {
                return Err(ServiceError::invalid_input(format!(
                    "'{}' acts on no zone, so its grant must cover all zones: omit zone_name",
                    action
                )));
            }
            Some(zone::lookup_by_name(cx, &zone::normalize_name(zone_name)?).await?)
        }
    };

    let mut tx = transaction::begin_tx(cx, "failed to create role grant").await?;
    let result = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        bindizr_db::role_grant::create_tx(
            &mut tx,
            RoleGrant {
                id: RoleGrantId::UNWRITTEN,
                role_id: role.id,
                zone_scope: zone
                    .as_ref()
                    .map_or(RoleZoneScope::All, |zone| RoleZoneScope::Zone(zone.id)),
                actions,
                record_name_pattern,
                record_types,
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|e| {
            // The zone or role can go between the lookups above and this insert;
            // the FK reports it.
            if e.is_foreign_key_violation() {
                ServiceError::ZoneNotFound("zone or role no longer exists".to_string())
            } else {
                e.into()
            }
        })
    }
    .await;
    let grant = transaction::finish_tx(tx, result, "failed to create role grant").await?;

    Ok(GetRoleGrantResponse::from_grant(
        &grant,
        &role.name,
        zone.as_ref().map(|zone| &zone.name),
    ))
}

/// Every grant of `role_name`, with the zone each covers.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    role_name: &str,
    page: PageRequest,
) -> Result<PaginatedResponse<GetRoleGrantResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = super::lookup_by_name(cx, role_name).await?;
    list_by_role(cx, &role, page).await
}

/// The grants of `token`'s role; any token may read its own.
pub async fn list_self(
    cx: &Context,
    token: &ApiToken,
    page: PageRequest,
) -> Result<PaginatedResponse<GetRoleGrantResponse>, ServiceError> {
    let role = bindizr_db::role::get(cx.db(), token.role_id)
        .await?
        .ok_or_else(|| ServiceError::role_not_found(token.role_id))?;
    list_by_role(cx, &role, page).await
}

/// Revoke one of `role_name`'s grants by id. An id that belongs to another
/// role reads as not found.
pub async fn revoke(
    cx: &Context,
    caller: &Caller,
    role_name: &str,
    grant_id: RoleGrantId,
) -> Result<(), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = super::lookup_by_name(cx, role_name).await?;
    super::refuse_builtin(&role)?;
    let grant = bindizr_db::role_grant::get(cx.db(), grant_id)
        .await?
        .filter(|grant| grant.role_id == role.id)
        .ok_or_else(|| ServiceError::role_grant_not_found(grant_id))?;

    let mut tx = transaction::begin_tx(cx, "failed to revoke role grant").await?;
    let result = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        Ok(bindizr_db::role_grant::delete_tx(&mut tx, grant.id).await?)
    }
    .await;
    transaction::finish_tx(tx, result, "failed to revoke role grant").await
}

/// A role's grants as responses, each with the name of the zone it covers.
async fn list_by_role(
    cx: &Context,
    role: &Role,
    page: PageRequest,
) -> Result<PaginatedResponse<GetRoleGrantResponse>, ServiceError> {
    let grants = bindizr_db::role_grant::list_by_role_id(cx.db(), role.id).await?;
    let zone_names: HashMap<ZoneId, ZoneName> = bindizr_db::zone::list_all(cx.db())
        .await?
        .into_iter()
        .map(|zone| (zone.id, zone.name))
        .collect();

    build_page(
        grants
            .iter()
            .map(|grant| {
                let zone_name = grant
                    .zone_scope
                    .zone_id()
                    .and_then(|zone_id| zone_names.get(&zone_id));
                GetRoleGrantResponse::from_grant(grant, &role.name, zone_name)
            })
            .collect(),
        page.limit,
        page.offset,
    )
}
