//! Creates, lists, and deletes roles, which API tokens and TSIG keys authenticate into.

use std::collections::HashMap;

use bindizr_core::model::{
    role::{Role, RoleId},
    role_grant::Action,
};
use chrono::Utc;

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    pagination::build_page,
    text::{MAX_COLUMN_TEXT_LEN, normalize_description, normalize_identifier},
    transaction,
    types::{CreateRoleRequest, GetRoleResponse, PageRequest, PaginatedResponse},
};

/// Create a role holding no grants yet.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateRoleRequest,
) -> Result<GetRoleResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let name = normalize_role_name(&request.name)?;
    let description =
        normalize_description(request.description.as_deref(), ServiceError::invalid_input)?;

    // Friendly pre-check; the UNIQUE(name) backstop covers the race.
    if bindizr_db::role::get_by_name(cx.db(), &name)
        .await?
        .is_some()
    {
        return Err(ServiceError::role_conflict(&name));
    }

    let mut tx = transaction::begin_tx(cx, "failed to create role").await?;
    let result = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        bindizr_db::role::create_tx(
            &mut tx,
            Role {
                id: RoleId::UNWRITTEN,
                name: name.clone(),
                description,
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|e| {
            // A create that raced past the pre-check trips UNIQUE(name); the
            // backstop reads as the same conflict.
            if e.is_unique_violation() {
                ServiceError::role_conflict(&name)
            } else {
                e.into()
            }
        })
    }
    .await;
    let role = transaction::finish_tx(tx, result, "failed to create role").await?;
    Ok(GetRoleResponse {
        id: role.id,
        builtin: role.is_builtin(),
        name: role.name,
        description: role.description,
        grant_count: 0,
        token_count: 0,
        tsig_key_count: 0,
        created_at: role.created_at,
    })
}

/// List all roles, each with how many grants, tokens, and keys it has.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageRequest,
) -> Result<PaginatedResponse<GetRoleResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let roles = bindizr_db::role::list_all(cx.db()).await?;
    // Management collections are small, so each is read once and counted
    // here rather than queried per role.
    let mut grants: HashMap<RoleId, u64> = HashMap::new();
    for grant in bindizr_db::role_grant::list_all(cx.db()).await? {
        *grants.entry(grant.role_id).or_default() += 1;
    }
    let mut tokens: HashMap<RoleId, u64> = HashMap::new();
    for token in bindizr_db::api_token::list_all(cx.db()).await? {
        *tokens.entry(token.role_id).or_default() += 1;
    }
    let mut keys: HashMap<RoleId, u64> = HashMap::new();
    for tsig_key in bindizr_db::tsig_key::list_all(cx.db()).await? {
        *keys.entry(tsig_key.role_id).or_default() += 1;
    }
    build_page(
        roles
            .into_iter()
            .map(|role| GetRoleResponse {
                id: role.id,
                builtin: role.is_builtin(),
                grant_count: grants.get(&role.id).copied().unwrap_or(0),
                token_count: tokens.get(&role.id).copied().unwrap_or(0),
                tsig_key_count: keys.get(&role.id).copied().unwrap_or(0),
                name: role.name,
                description: role.description,
                created_at: role.created_at,
            })
            .collect(),
        page.limit,
        page.offset,
    )
}

/// Fetch one role by name, with how many grants, tokens, and keys it has.
pub async fn get(
    cx: &Context,
    caller: &Caller,
    name: &str,
) -> Result<GetRoleResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = lookup_by_name(cx, name).await?;
    let grants = bindizr_db::role_grant::list_by_role_id(cx.db(), role.id).await?;
    let tokens = bindizr_db::api_token::list_by_role_id(cx.db(), role.id).await?;
    let keys = bindizr_db::tsig_key::list_by_role_id(cx.db(), role.id).await?;
    Ok(GetRoleResponse {
        id: role.id,
        builtin: role.is_builtin(),
        grant_count: grants.len() as u64,
        token_count: tokens.len() as u64,
        tsig_key_count: keys.len() as u64,
        name: role.name,
        description: role.description,
        created_at: role.created_at,
    })
}

/// Delete a role and its grants; refused for the built-in role and while a credential holds it.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = lookup_by_name(cx, name).await?;
    refuse_builtin(&role)?;

    // Named, so the refusal says which credentials to move or delete first.
    let tokens: Vec<String> = bindizr_db::api_token::list_by_role_id(cx.db(), role.id)
        .await?
        .into_iter()
        .map(|token| token.name)
        .collect();
    let keys: Vec<String> = bindizr_db::tsig_key::list_by_role_id(cx.db(), role.id)
        .await?
        .into_iter()
        .map(|tsig_key| tsig_key.name)
        .collect();
    if !tokens.is_empty() || !keys.is_empty() {
        return Err(ServiceError::role_in_use(&role.name, &tokens, &keys));
    }

    let mut tx = transaction::begin_tx(cx, "failed to delete role").await?;
    let result = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        bindizr_db::role::delete_tx(&mut tx, role.id)
            .await
            .map_err(|e| {
                // A credential that took the role between the counts above and
                // this delete trips the FK: the same in-use conflict.
                if e.is_foreign_key_violation() {
                    ServiceError::RoleInUse(format!(
                        "role '{}' is still held by an API token or TSIG key",
                        role.name
                    ))
                } else {
                    e.into()
                }
            })
    }
    .await;
    transaction::finish_tx(tx, result, "failed to delete role").await
}

/// Load a role by name or return a not-found error.
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<Role, ServiceError> {
    bindizr_db::role::get_by_name(cx.db(), &normalize_role_name(name)?)
        .await?
        .ok_or_else(|| ServiceError::role_not_found(name))
}

/// Refuse a change to the built-in role.
fn refuse_builtin(role: &Role) -> Result<(), ServiceError> {
    if role.is_builtin() {
        return Err(ServiceError::invalid_input(format!(
            "role '{}' is built in and cannot be changed or deleted",
            role.name
        )));
    }
    Ok(())
}

/// Lowercased so one name means one role on every backend, and kept to one
/// URL path segment for `/roles/{name}`.
fn normalize_role_name(name: &str) -> Result<String, ServiceError> {
    let name = normalize_identifier(name, "role name", MAX_COLUMN_TEXT_LEN)?;
    // Dot segments get normalized away.
    if name == "." || name == ".." {
        return Err(ServiceError::invalid_input(format!(
            "role name must not be '{name}'"
        )));
    }
    Ok(name)
}

pub mod grant;
