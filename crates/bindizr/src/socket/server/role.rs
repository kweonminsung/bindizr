use bindizr_core::model::role_grant::RoleGrantId;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::role::grant;
use bindizr_service::types::{
    CreateRoleGrantRequest, CreateRoleRequest, MessageResponse, PageRequest, PaginatedResponse,
    RoleGrantResponse, RoleResponse, SingleRoleGrantResponse, SingleRoleResponse,
};
use bindizr_service::{Context, role};

use crate::socket::types::DaemonResponse;

/// Create a role from the control request.
pub(crate) async fn create_role(
    cx: &Context,
    request: &CreateRoleRequest,
) -> Result<DaemonResponse<SingleRoleResponse>, ServiceError> {
    let response = role::create(cx, &Caller::socket(), request).await?;
    Ok(DaemonResponse {
        message: "Role created successfully".to_string(),
        data: SingleRoleResponse { role: response },
    })
}

/// List the requested roles.
pub(crate) async fn list_roles(
    cx: &Context,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<RoleResponse>>, ServiceError> {
    let response = role::list(cx, &Caller::socket(), page).await?;
    Ok(DaemonResponse {
        message: "Roles retrieved successfully".to_string(),
        data: response,
    })
}

/// Get the requested role.
pub(crate) async fn get_role(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<SingleRoleResponse>, ServiceError> {
    let response = role::get_by_name(cx, &Caller::socket(), name).await?;
    Ok(DaemonResponse {
        message: "Role retrieved successfully".to_string(),
        data: SingleRoleResponse { role: response },
    })
}

/// Delete the requested role.
pub(crate) async fn delete_role(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let response = role::delete(cx, &Caller::socket(), name).await?;

    Ok(response.into())
}

/// Grant the requested role actions.
pub(crate) async fn create_role_grant(
    cx: &Context,
    role_name: &str,
    request: &CreateRoleGrantRequest,
) -> Result<DaemonResponse<SingleRoleGrantResponse>, ServiceError> {
    let response = grant::create(cx, &Caller::socket(), role_name, request).await?;
    Ok(DaemonResponse {
        message: "Role grant created successfully".to_string(),
        data: SingleRoleGrantResponse {
            role_grant: response,
        },
    })
}

/// List the requested role's grants.
pub(crate) async fn list_role_grants(
    cx: &Context,
    role_name: &str,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<RoleGrantResponse>>, ServiceError> {
    let response = grant::list(cx, &Caller::socket(), role_name, page).await?;
    Ok(DaemonResponse {
        message: "Role grants retrieved successfully".to_string(),
        data: response,
    })
}

/// Revoke one of the requested role's grants.
pub(crate) async fn delete_role_grant(
    cx: &Context,
    role_name: &str,
    grant_id: RoleGrantId,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let response = grant::revoke(cx, &Caller::socket(), role_name, grant_id).await?;

    Ok(response.into())
}
