use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    token::{TokenService, grant::TokenGrantService},
    types::{
        CreateTokenGrantRequest, CreateTokenRequest, ErrorResponse, GetTokenGrantResponse,
        GetTokenResponse, MessageResponse, TokenGrantListResponse, TokenGrantResponse,
        TokenListResponse, TokenResponse,
    },
};
use serde::Deserialize;

use crate::api::{
    GrantIdParam, RequestCaller, ZoneNameParam, error::ApiError, middleware::body_parser::JsonBody,
};

pub(crate) struct TokenApi;

impl TokenApi {
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/tokens", routing::get(get_tokens))
            .route("/tokens", routing::post(create_token))
            .route("/tokens/{name}", routing::delete(delete_token))
            .route("/tokens/{name}/grants", routing::get(get_token_grants))
            .route("/tokens/{name}/grants", routing::post(create_token_grant))
            .route(
                "/tokens/{name}/grants/{id}",
                routing::delete(delete_token_grant),
            )
            .route(
                "/zones/{name}/token-grants",
                routing::get(get_zone_token_grants),
            )
    }
}

#[derive(Deserialize)]
pub(crate) struct TokenNameParam {
    pub(crate) name: String,
}

#[utoipa::path(
        get,
        path = "/tokens",
        tag = "Token",
        summary = "List all API tokens",
        description = "Lists every API token without its secret; a secret is shown once, in the create response.",
        responses(
            (status = 200, description = "All API tokens", body = TokenListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List all API tokens (secrets omitted).
pub(crate) async fn get_tokens(RequestCaller(caller): RequestCaller) -> Result<Response, ApiError> {
    let tokens = TokenService::list(&caller).await?;
    let response = TokenListResponse {
        tokens: tokens.iter().map(GetTokenResponse::from_token).collect(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/tokens",
        tag = "Token",
        summary = "Create an API token",
        description = "Creates an API token and returns its secret, the one time it is shown. A scoped token (the default) acts only on the zones it is later granted; `global` makes it cover every zone and the zone plane, fixed at creation.",
        request_body = CreateTokenRequest,
        responses(
            (status = 201, description = "API token created; the response carries the secret", body = TokenResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 409, description = "An API token with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create an API token; the secret is returned once, here.
pub(crate) async fn create_token(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateTokenRequest>,
) -> Result<Response, ApiError> {
    let token = TokenService::create(
        &caller,
        &body.name,
        body.description.as_deref(),
        body.expires_in_days,
        body.global,
    )
    .await?;
    let response = TokenResponse {
        token: GetTokenResponse::from_token(&token),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

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
/// Delete an API token by name.
pub(crate) async fn delete_token(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TokenNameParam>,
) -> Result<Response, ApiError> {
    TokenService::delete(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "Token deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        get,
        path = "/tokens/{name}/grants",
        tag = "Token",
        summary = "List an API token's grants",
        params(
            ("name" = String, Path, description = "The name of the API token.")
        ),
        responses(
            (status = 200, description = "The token's grants", body = TokenGrantListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Token not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List an API token's grants.
pub(crate) async fn get_token_grants(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TokenNameParam>,
) -> Result<Response, ApiError> {
    let grants = TokenGrantService::list_by_token(&caller, &params.name).await?;
    let response = TokenGrantListResponse {
        token_grants: grants
            .iter()
            .map(GetTokenGrantResponse::from_grant)
            .collect(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/tokens/{name}/grants",
        tag = "Token",
        summary = "Grant an API token record rights in a zone",
        description = "Grants the token record-plane rights in the named zone, optionally restricted by record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record types (`*` or a comma-separated list). Global tokens are rejected: they already cover every zone and never carry grants.",
        params(
            ("name" = String, Path, description = "The name of the API token.")
        ),
        request_body = CreateTokenGrantRequest,
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
/// Grant an API token record rights in a zone.
pub(crate) async fn create_token_grant(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TokenNameParam>,
    JsonBody(body): JsonBody<CreateTokenGrantRequest>,
) -> Result<Response, ApiError> {
    let grant = TokenGrantService::grant(
        &caller,
        &params.name,
        &body.zone_name,
        body.record_name_pattern.as_deref(),
        body.record_types.as_deref(),
    )
    .await?;
    let response = TokenGrantResponse {
        token_grant: GetTokenGrantResponse::from_grant(&grant),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

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
/// Revoke one of an API token's grants by grant id.
pub(crate) async fn delete_token_grant(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<GrantIdParam>,
) -> Result<Response, ApiError> {
    TokenGrantService::revoke(&caller, &params.name, params.id).await?;
    let response = MessageResponse {
        message: "Token grant revoked successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/token-grants",
        tag = "Token",
        summary = "List the API token grants that apply to a zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Grants covering the zone", body = TokenGrantListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List the API token grants that apply to a zone.
pub(crate) async fn get_zone_token_grants(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    let grants = TokenGrantService::list_by_zone(&caller, &params.name).await?;
    let response = TokenGrantListResponse {
        token_grants: grants
            .iter()
            .map(GetTokenGrantResponse::from_grant)
            .collect(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
