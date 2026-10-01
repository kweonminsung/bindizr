//! Creates, lists, and deletes roles, which API tokens and TSIG keys authenticate into.

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
    types::{CreateRoleRequest, GetRoleResponse, PageRequest, PaginatedResponse},
};

/// Create a role holding no grants yet.
pub async fn create(
    cx: &Context,
    caller: &Caller,
    request: &CreateRoleRequest,
) -> Result<Role, ServiceError> {
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

    bindizr_db::role::create(
        cx.db(),
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

/// List all roles.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    page: PageRequest,
) -> Result<PaginatedResponse<GetRoleResponse>, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let roles = bindizr_db::role::list_all(cx.db()).await?;
    build_page(
        roles.iter().map(GetRoleResponse::from).collect(),
        page.limit,
        page.offset,
    )
}

/// Fetch one role by name.
pub async fn get(cx: &Context, caller: &Caller, name: &str) -> Result<Role, ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    lookup_by_name(cx, name).await
}

/// Delete a role and its grants; refused for the built-in role and while a credential holds it.
pub async fn delete(cx: &Context, caller: &Caller, name: &str) -> Result<(), ServiceError> {
    caller.authorize_action(Action::AccessManage)?;

    let role = lookup_by_name(cx, name).await?;
    refuse_builtin(&role)?;

    let tokens = bindizr_db::api_token::count_by_role_id(cx.db(), role.id).await?;
    let keys = bindizr_db::tsig_key::count_by_role_id(cx.db(), role.id).await?;
    if tokens > 0 || keys > 0 {
        return Err(ServiceError::role_in_use(&role.name, tokens, keys));
    }

    bindizr_db::role::delete(cx.db(), role.id)
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
