use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    token::{TokenService, grant::TokenGrantService},
    types::{
        CreateGrantRequest, CreateTokenRequest, CreatedTokenResponse, DEFAULT_PAGE_LIMIT,
        ErrorResponse, GetTokenGrantResponse, GetTokenResponse, MessageResponse, PageFilter,
        PaginatedResponse, TokenGrantResponse, TokenResponse,
    },
};

use crate::api::{
    AuthenticatedToken, NameIdParam, NameParam, RequestCaller,
    error::{ApiError, Path, Query},
    middleware::body_parser::JsonBody,
};

pub(crate) struct TokenApi;

impl TokenApi {
    /// Build the token API routes.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/tokens", routing::get(list_tokens))
            .route("/tokens", routing::post(create_token))
            .route("/tokens/self", routing::get(get_self_token))
            .route("/tokens/self/grants", routing::get(list_self_token_grants))
            .route("/tokens/{name}", routing::delete(delete_token))
            .route("/tokens/{name}/grants", routing::get(list_token_grants))
            .route("/tokens/{name}/grants", routing::post(create_token_grant))
            .route(
                "/tokens/{name}/grants/{id}",
                routing::delete(delete_token_grant),
            )
            .route(
                "/zones/{name}/token-grants",
                routing::get(list_zone_token_grants),
            )
    }
}

/// List all API tokens (secrets omitted).
#[utoipa::path(
        get,
        path = "/tokens",
        tag = "Token",
        summary = "List all API tokens",
        params(PageFilter),
        description = "Lists every API token without its secret; a secret is shown once, in the create response.",
        responses(
            (status = 200, description = "All API tokens", body = PaginatedResponse<GetTokenResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_tokens(
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TokenService::list(&caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create an API token; the secret is returned once, here.
#[utoipa::path(
        post,
        path = "/tokens",
        tag = "Token",
        summary = "Create an API token",
        description = "Creates an API token and returns its secret, the one time it is shown. A scoped token (the default) acts only on the zones it is later granted; `global` makes it cover every zone and the zone plane, fixed at creation.",
        request_body = CreateTokenRequest,
        responses(
            (status = 201, description = "API token created; the response carries the secret", body = CreatedTokenResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 409, description = "An API token with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_token(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateTokenRequest>,
) -> Result<Response, ApiError> {
    let (token, secret) = TokenService::create(
        &caller,
        &body.name,
        body.description.as_deref(),
        body.expires_in_days,
        body.global,
    )
    .await?;
    let response = CreatedTokenResponse {
        token: GetTokenResponse::from_token(&token),
        secret,
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Describe the token the request authenticated with.
#[utoipa::path(
        get,
        path = "/tokens/self",
        tag = "Token",
        summary = "Describe the API token making the request",
        description = "The calling token's own metadata, never its secret; any token may read itself. With authentication disabled no token is presented, so this answers 401.",
        responses(
            (status = 200, description = "The calling token", body = TokenResponse),
            (status = 401, description = "Unauthorized, or no token presented", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_self_token(
    AuthenticatedToken(token): AuthenticatedToken,
) -> Result<Response, ApiError> {
    let response = TokenResponse {
        token: GetTokenResponse::from_token(&token),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List the grants of the token the request authenticated with.
#[utoipa::path(
        get,
        path = "/tokens/self/grants",
        tag = "Token",
        summary = "List the grants of the API token making the request",
        params(PageFilter),
        description = "The calling token's grants; any token may read its own. A global token holds none, so its list is empty. With authentication disabled no token is presented, so this answers 401.",
        responses(
            (status = 200, description = "The calling token's grants", body = PaginatedResponse<GetTokenGrantResponse>),
            (status = 401, description = "Unauthorized, or no token presented", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_self_token_grants(
    AuthenticatedToken(token): AuthenticatedToken,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TokenGrantService::list_self(&token, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete an API token by name.
#[utoipa::path(
        delete,
        path = "/tokens/{name}",
        tag = "Token",
        summary = "Delete an API token",
        description = "Deletes an API token; its grants go with it.",
        params(
            ("name" = String, Path, description = "The name of the API token.")
        ),
        responses(
            (status = 200, description = "API token deleted", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Token not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_token(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParam>,
) -> Result<Response, ApiError> {
    TokenService::delete(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "Token deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List an API token's grants.
#[utoipa::path(
        get,
        path = "/tokens/{name}/grants",
        tag = "Token",
        summary = "List an API token's grants",
        params(
            ("name" = String, Path, description = "The name of the API token."),
            ("limit" = Option<u32>, Query, minimum = 1, maximum = 1000, description = "Grants per page; defaults to 50."),
            ("offset" = Option<u64>, Query, description = "Number of grants to skip.")
        ),
        responses(
            (status = 200, description = "The token's grants", body = PaginatedResponse<GetTokenGrantResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Token not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_token_grants(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParam>,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TokenGrantService::list_by_token(&caller, &params.name, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Grant an API token record rights in a zone.
#[utoipa::path(
        post,
        path = "/tokens/{name}/grants",
        tag = "Token",
        summary = "Grant an API token record rights in a zone",
        description = "Grants the token record-plane rights in the named zone, optionally restricted by record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record types (`*` or a comma-separated list). Global tokens are rejected: they already cover every zone and never carry grants.",
        params(
            ("name" = String, Path, description = "The name of the API token.")
        ),
        request_body = CreateGrantRequest,
        responses(
            (status = 201, description = "Token grant created", body = TokenGrantResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Token or zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_token_grant(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParam>,
    JsonBody(body): JsonBody<CreateGrantRequest>,
) -> Result<Response, ApiError> {
    let grant = TokenGrantService::grant(
        &caller,
        &params.name,
        &body.zone_name,
        body.record_name_pattern.as_deref(),
        body.record_types.as_deref(),
        body.can_write,
    )
    .await?;
    let response = TokenGrantResponse {
        token_grant: GetTokenGrantResponse::from_grant(&grant),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Revoke one of an API token's grants by grant id.
#[utoipa::path(
        delete,
        path = "/tokens/{name}/grants/{id}",
        tag = "Token",
        summary = "Revoke one of an API token's grants",
        params(
            ("name" = String, Path, description = "The name of the API token."),
            ("id" = i32, Path, description = "The id of the grant to revoke.")
        ),
        responses(
            (status = 200, description = "Token grant revoked", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Token or grant not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_token_grant(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameIdParam>,
) -> Result<Response, ApiError> {
    TokenGrantService::revoke(&caller, &params.name, params.id).await?;
    let response = MessageResponse {
        message: "Token grant revoked successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List the API token grants that apply to a zone.
#[utoipa::path(
        get,
        path = "/zones/{name}/token-grants",
        tag = "Token",
        summary = "List the API token grants that apply to a zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("limit" = Option<u32>, Query, minimum = 1, maximum = 1000, description = "Grants per page; defaults to 50."),
            ("offset" = Option<u64>, Query, description = "Number of grants to skip.")
        ),
        responses(
            (status = 200, description = "Grants covering the zone", body = PaginatedResponse<GetTokenGrantResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_zone_token_grants(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParam>,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TokenGrantService::list_by_zone(&caller, &params.name, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
