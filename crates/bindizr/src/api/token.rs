use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use bindizr_service::role::grant;
use bindizr_service::types::{
    ApiTokenFilter, ApiTokenResponse, CreateApiTokenRequest, CreateApiTokenResponse, ErrorResponse,
    MessageResponse, PageRequest, PaginatedResponse, RoleGrantResponse, SingleApiTokenResponse,
};
use bindizr_service::{Context, token};

use crate::api::error::ApiError;
use crate::api::extract::{AuthenticatedToken, JsonBody, Path, Query, RequestCaller};
use crate::api::params::NameParams;
use crate::api::query::DEFAULT_PAGE_LIMIT;

/// Build the token API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/tokens", routing::get(list_tokens))
        .route("/tokens", routing::post(create_token))
        .route("/tokens/self", routing::get(get_self_token))
        .route("/tokens/self/grants", routing::get(list_self_token_grants))
        .route("/tokens/{name}", routing::delete(delete_token))
}

/// List all API tokens (secrets omitted).
#[utoipa::path(
        get,
        path = "/tokens",
        tag = "Token",
        summary = "List API tokens",
        description = "Lists API tokens without their secrets, every one or only those authenticating into `role_name`; a secret is shown once, in the create response.",
        params(ApiTokenFilter),
        responses(
            (status = 200, description = "All API tokens", body = PaginatedResponse<ApiTokenResponse>),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_tokens(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut filter): Query<ApiTokenFilter>,
) -> Result<Response, ApiError> {
    filter.limit = filter.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = token::list(&cx, &caller, &filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create an API token; the secret is returned once, here.
#[utoipa::path(
        post,
        path = "/tokens",
        tag = "Token",
        summary = "Create an API token",
        description = "Creates an API token in a role and returns its secret, the one time it is shown. The role's grants decide what the token may do.",
        request_body = CreateApiTokenRequest,
        responses(
            (status = 201, description = "API token created; the response carries the secret", body = CreateApiTokenResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Role not found", body = ErrorResponse),
            (status = 409, description = "An API token with the same name already exists", body = ErrorResponse),
            (status = 413, description = "Request body exceeds the route's limit", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_token(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateApiTokenRequest>,
) -> Result<Response, ApiError> {
    let (token, secret) = token::create(&cx, &caller, &body).await?;
    let response = CreateApiTokenResponse { token, secret };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Describe the token the request authenticated with.
#[utoipa::path(
        get,
        path = "/tokens/self",
        tag = "Token",
        summary = "Describe the API token making the request",
        description = "The calling token's own metadata, never its secret; any token may read itself. With authentication disabled no token is presented, so this answers 404.",
        responses(
            (status = 200, description = "The calling token", body = SingleApiTokenResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "No token presented: authentication is disabled", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_self_token(
    State(cx): State<Arc<Context>>,
    AuthenticatedToken(token): AuthenticatedToken,
) -> Result<Response, ApiError> {
    let token = token::get_self(&cx, &token).await?;
    let response = SingleApiTokenResponse { token };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List the grants of the role the request's token authenticates into.
#[utoipa::path(
        get,
        path = "/tokens/self/grants",
        tag = "Token",
        summary = "List the grants of the calling API token's role",
        description = "The grants of the calling token's role; any token may read its own. With authentication disabled no token is presented, so this answers 404.",
        params(PageRequest),
        responses(
            (status = 200, description = "The calling token's grants", body = PaginatedResponse<RoleGrantResponse>),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "No token presented: authentication is disabled", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_self_token_grants(
    State(cx): State<Arc<Context>>,
    AuthenticatedToken(token): AuthenticatedToken,
    Query(mut page): Query<PageRequest>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = grant::list_self(&cx, &token, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete an API token by name.
#[utoipa::path(
        delete,
        path = "/tokens/{name}",
        tag = "Token",
        summary = "Delete an API token",
        description = "Deletes an API token; its role and the role's grants stay.",
        params(
            ("name" = String, Path, description = "The name of the API token.")
        ),
        responses(
            (status = 200, description = "API token deleted", body = MessageResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Token not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_token(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let response = token::delete(&cx, &caller, &params.name).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
