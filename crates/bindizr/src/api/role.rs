use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_core::model::role_grant::RoleGrantId;
use bindizr_service::{
    Context,
    role::{self, grant},
    types::{
        CreateRoleGrantRequest, CreateRoleRequest, DEFAULT_PAGE_LIMIT, ErrorResponse,
        GetRoleGrantResponse, GetRoleResponse, MessageResponse, PageRequest, PaginatedResponse,
        RoleGrantResponse, RoleResponse,
    },
};

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
        middleware::body_parser::JsonBody,
    },
    params::{NameIdParams, NameParams},
};

/// Build the role API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/roles", routing::get(list_roles))
        .route("/roles", routing::post(create_role))
        .route("/roles/{name}", routing::get(get_role))
        .route("/roles/{name}", routing::delete(delete_role))
        .route("/roles/{name}/grants", routing::get(list_role_grants))
        .route("/roles/{name}/grants", routing::post(create_role_grant))
        .route(
            "/roles/{name}/grants/{id}",
            routing::delete(delete_role_grant),
        )
}

/// List all roles.
#[utoipa::path(
        get,
        path = "/roles",
        tag = "Role",
        summary = "List all roles",
        params(PageRequest),
        responses(
            (status = 200, description = "All roles", body = PaginatedResponse<GetRoleResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_roles(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageRequest>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = role::list(&cx, &caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create a role holding no grants yet.
#[utoipa::path(
        post,
        path = "/roles",
        tag = "Role",
        summary = "Create a role",
        description = "Creates a role with no grants. API tokens and TSIG keys authenticate into a role, and its grants decide what they may do.",
        request_body = CreateRoleRequest,
        responses(
            (status = 201, description = "Role created", body = RoleResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 409, description = "A role with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_role(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateRoleRequest>,
) -> Result<Response, ApiError> {
    let role = role::create(&cx, &caller, &body).await?;
    let response = RoleResponse {
        role: GetRoleResponse::from(&role),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Get one role by name.
#[utoipa::path(
        get,
        path = "/roles/{name}",
        tag = "Role",
        summary = "Get a specific role",
        params(
            ("name" = String, Path, description = "The name of the role.")
        ),
        responses(
            (status = 200, description = "The role", body = RoleResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_role(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let role = role::get(&cx, &caller, &params.name).await?;
    let response = RoleResponse {
        role: GetRoleResponse::from(&role),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a role that no credential holds.
#[utoipa::path(
        delete,
        path = "/roles/{name}",
        tag = "Role",
        summary = "Delete a role",
        description = "Deletes a role and its grants. Refused for the built-in `admin` role and while an API token or TSIG key still authenticates into it.",
        params(
            ("name" = String, Path, description = "The name of the role.")
        ),
        responses(
            (status = 200, description = "Role deleted", body = MessageResponse),
            (status = 400, description = "The built-in role cannot be deleted", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role not found", body = ErrorResponse),
            (status = 409, description = "An API token or TSIG key still holds the role", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_role(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    role::delete(&cx, &caller, &params.name).await?;
    let response = MessageResponse {
        message: "Role deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List a role's grants.
#[utoipa::path(
        get,
        path = "/roles/{name}/grants",
        tag = "Role",
        summary = "List a role's grants",
        params(
            ("name" = String, Path, description = "The name of the role."),
            ("limit" = Option<u32>, Query, minimum = 1, maximum = 1000, description = "Grants per page; defaults to 50."),
            ("offset" = Option<u64>, Query, description = "Number of grants to skip.")
        ),
        responses(
            (status = 200, description = "The role's grants", body = PaginatedResponse<GetRoleGrantResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_role_grants(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(mut page): Query<PageRequest>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = grant::list(&cx, &caller, &params.name, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Grant a role actions in one zone or every zone.
#[utoipa::path(
        post,
        path = "/roles/{name}/grants",
        tag = "Role",
        summary = "Grant a role actions",
        description = "Grants the role actions in the named zone, or in every zone when `zone_name` is omitted. The record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record types (`*` or a comma-separated list) narrow its `record:*` actions only. The built-in `admin` role cannot be changed.",
        params(
            ("name" = String, Path, description = "The name of the role.")
        ),
        request_body = CreateRoleGrantRequest,
        responses(
            (status = 201, description = "Role grant created", body = RoleGrantResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role or zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_role_grant(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    JsonBody(body): JsonBody<CreateRoleGrantRequest>,
) -> Result<Response, ApiError> {
    let role_grant = grant::create(&cx, &caller, &params.name, &body).await?;
    let response = RoleGrantResponse { role_grant };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Revoke one of a role's grants by grant id.
#[utoipa::path(
        delete,
        path = "/roles/{name}/grants/{id}",
        tag = "Role",
        summary = "Revoke one of a role's grants",
        params(
            ("name" = String, Path, description = "The name of the role."),
            ("id" = i32, Path, description = "The id of the grant to revoke.")
        ),
        responses(
            (status = 200, description = "Role grant revoked", body = MessageResponse),
            (status = 400, description = "The built-in role cannot be changed", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role or grant not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_role_grant(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameIdParams>,
) -> Result<Response, ApiError> {
    grant::revoke(&cx, &caller, &params.name, RoleGrantId::from(params.id)).await?;
    let response = MessageResponse {
        message: "Role grant revoked successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
