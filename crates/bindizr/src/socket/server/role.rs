use bindizr_core::model::role_grant::RoleGrantId;
use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    role::{self, grant},
    types::{
        CreateRoleGrantRequest, CreateRoleRequest, GetRoleGrantResponse, GetRoleResponse,
        MessageResponse, PageRequest, PaginatedResponse, RoleGrantResponse, RoleResponse,
    },
};

use crate::socket::types::DaemonResponse;

/// Create a role from the control request.
pub(crate) async fn create_role(
    cx: &Context,
    request: &CreateRoleRequest,
) -> Result<DaemonResponse<RoleResponse>, ServiceError> {
    let role = role::create(cx, &Caller::socket(), request).await?;
    Ok(DaemonResponse {
        message: "Role created successfully".to_string(),
        data: RoleResponse {
            role: GetRoleResponse::from(&role),
        },
    })
}

/// List the requested roles.
pub(crate) async fn list_roles(
    cx: &Context,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<GetRoleResponse>>, ServiceError> {
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
) -> Result<DaemonResponse<RoleResponse>, ServiceError> {
    let role = role::get(cx, &Caller::socket(), name).await?;
    Ok(DaemonResponse {
        message: "Role retrieved successfully".to_string(),
        data: RoleResponse {
            role: GetRoleResponse::from(&role),
        },
    })
}

/// Delete the requested role.
pub(crate) async fn delete_role(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    role::delete(cx, &Caller::socket(), name).await?;
    let message = format!("Role '{}' deleted successfully", name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Grant the requested role actions.
pub(crate) async fn create_role_grant(
    cx: &Context,
    role_name: &str,
    request: &CreateRoleGrantRequest,
) -> Result<DaemonResponse<RoleGrantResponse>, ServiceError> {
    let role_grant = grant::create(cx, &Caller::socket(), role_name, request).await?;
    Ok(DaemonResponse {
        message: "Role grant created successfully".to_string(),
        data: RoleGrantResponse { role_grant },
    })
}

/// List the requested role's grants.
pub(crate) async fn list_role_grants(
    cx: &Context,
    role_name: &str,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<GetRoleGrantResponse>>, ServiceError> {
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
    id: RoleGrantId,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    grant::revoke(cx, &Caller::socket(), role_name, id).await?;
    let message = "Role grant revoked successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
