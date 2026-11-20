//! Creates, lists, and deletes roles, which API tokens and TSIG keys authenticate into.

pub mod grant;

use std::collections::HashMap;

use bindizr_core::model::audit_log::{AuditEntity, AuditOperation};
use bindizr_core::model::role::{Role, RoleId};
use bindizr_core::model::role_grant::Action;
use chrono::Utc;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::text::MAX_COLUMN_TEXT_LEN;
use crate::types::{CreateRoleRequest, PageRequest, PaginatedResponse, RoleResponse};
use crate::{Context, audit, pagination, text, transaction};

/// Create a role holding no grants yet.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateRoleRequest,
) -> Result<RoleResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let name = normalize_name(&request.name)?;
    let description =
        text::normalize_description(request.description.as_deref(), ServiceError::invalid_input)?;

    // Friendly pre-check; the UNIQUE(name) backstop covers the race.
    if bindizr_db::role::get_by_name(cx.db(), &name)
        .await?
        .is_some()
    {
        return Err(ServiceError::role_conflict(&name));
    }

    let mut tx = transaction::begin_tx(cx, "failed to create role").await?;

    let apply_result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        let role = bindizr_db::role::create_tx(
            &mut tx,
            Role {
                id: RoleId::UNWRITTEN,
                name: name.clone(),
                description,
                created_at: Utc::now(),
            },
        )
        .await
        .map_err(|error| {
            // A create that raced past the pre-check trips UNIQUE(name); the
            // backstop reads as the same conflict.
            if error.is_unique_violation() {
                ServiceError::role_conflict(&name)
            } else {
                error.into()
            }
        })?;
        audit::save_tx(
            &mut tx,
            AuditEntity::Role,
            &role.name,
            AuditOperation::Create,
            role.description
                .as_ref()
                .map(|description| format!("description {description}")),
            caller.change_origin(),
        )
        .await?;

        Ok(role)
    }
    .await;

    let role = transaction::finish_tx(tx, apply_result, "failed to create role").await?;

    Ok(RoleResponse {
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
) -> Result<PaginatedResponse<RoleResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;
    pagination::validate_page_limit(page.limit)?;

    let roles = bindizr_db::role::list_all(cx.db()).await?;

    // Management collections are small, so each is read once and counted
    // here rather than queried per role.
    let mut grant_counts: HashMap<RoleId, u64> = HashMap::new();

    for grant in bindizr_db::role_grant::list_all(cx.db()).await? {
        *grant_counts.entry(grant.role_id).or_default() += 1;
    }

    let mut token_counts: HashMap<RoleId, u64> = HashMap::new();

    for token in bindizr_db::api_token::list_all(cx.db()).await? {
        *token_counts.entry(token.role_id).or_default() += 1;
    }

    let mut tsig_key_counts: HashMap<RoleId, u64> = HashMap::new();

    for tsig_key in bindizr_db::tsig_key::list_all(cx.db()).await? {
        *tsig_key_counts.entry(tsig_key.role_id).or_default() += 1;
    }

    Ok(pagination::build_page(
        roles
            .into_iter()
            .map(|role| RoleResponse {
                id: role.id,
                builtin: role.is_builtin(),
                grant_count: grant_counts.get(&role.id).copied().unwrap_or(0),
                token_count: token_counts.get(&role.id).copied().unwrap_or(0),
                tsig_key_count: tsig_key_counts.get(&role.id).copied().unwrap_or(0),
                name: role.name,
                description: role.description,
                created_at: role.created_at,
            })
            .collect(),
        page.limit,
        page.offset,
    ))
}

/// Get one role by name, with how many grants, tokens, and keys it has.
pub async fn get(cx: &Context, caller: &Caller, name: &str) -> Result<RoleResponse, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = lookup_by_name(cx, name).await?;
    let grants = bindizr_db::role_grant::list_by_role_id(cx.db(), role.id).await?;
    let tokens = bindizr_db::api_token::list_by_role_id(cx.db(), role.id).await?;
    let tsig_keys = bindizr_db::tsig_key::list_by_role_id(cx.db(), role.id).await?;

    Ok(RoleResponse {
        id: role.id,
        builtin: role.is_builtin(),
        grant_count: grants.len() as u64,
        token_count: tokens.len() as u64,
        tsig_key_count: tsig_keys.len() as u64,
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
    let token_names: Vec<String> = bindizr_db::api_token::list_by_role_id(cx.db(), role.id)
        .await?
        .into_iter()
        .map(|token| token.name)
        .collect();
    let tsig_key_names: Vec<String> = bindizr_db::tsig_key::list_by_role_id(cx.db(), role.id)
        .await?
        .into_iter()
        .map(|tsig_key| tsig_key.name)
        .collect();

    if !token_names.is_empty() || !tsig_key_names.is_empty() {
        return Err(ServiceError::role_in_use(
            &role.name,
            &token_names,
            &tsig_key_names,
        ));
    }

    let mut tx = transaction::begin_tx(cx, "failed to delete role").await?;

    let apply_result: Result<_, ServiceError> = async {
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_action(Action::AccessManage)?;
        let deleted = bindizr_db::role::delete_tx(&mut tx, role.id)
            .await
            .map_err(|error| {
                // A credential that took the role between the counts above and
                // this delete trips the FK: the same in-use conflict.
                if error.is_foreign_key_violation() {
                    ServiceError::RoleInUse(format!(
                        "role '{}' is still held by an API token or TSIG key",
                        role.name
                    ))
                } else {
                    error.into()
                }
            })?;

        // Removed meanwhile: not found, and no audit row for a deletion that was not one.
        if !deleted {
            return Err(ServiceError::role_not_found(&role.name));
        }

        // Its grants go with it, under the one row.
        audit::save_tx(
            &mut tx,
            AuditEntity::Role,
            &role.name,
            AuditOperation::Delete,
            None,
            caller.change_origin(),
        )
        .await
    }
    .await;

    transaction::finish_tx(tx, apply_result, "failed to delete role").await
}

/// Look up a role by name or return a not-found error.
pub(crate) async fn lookup_by_name(cx: &Context, name: &str) -> Result<Role, ServiceError> {
    bindizr_db::role::get_by_name(cx.db(), &normalize_name(name)?)
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

/// Normalize a role name: lowercased so one name means one role on every
/// backend, and kept to one URL path segment for `/roles/{name}`.
fn normalize_name(value: &str) -> Result<String, ServiceError> {
    text::normalize_identifier(value, "role name", MAX_COLUMN_TEXT_LEN)
}
