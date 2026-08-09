use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    types::{
        CreateZoneTokenPolicyRequest, ErrorResponse, GetZoneTokenPolicyResponse, MessageResponse,
        ZoneTokenPolicyListResponse, ZoneTokenPolicyResponse,
    },
    zone::token_policy::ZoneTokenPolicyService,
};
use serde::Deserialize;
use serde_json::json;

use crate::api::{RequestCaller, error::ApiError, middleware::body_parser::JsonBody};

/// Route group for zone token-policy endpoints.
pub(crate) struct TokenPolicyApi;

impl TokenPolicyApi {
    /// Build the router for zone token-policy endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route(
                "/zones/{name}/token-policies",
                routing::get(get_zone_token_policies),
            )
            .route(
                "/zones/{name}/token-policies",
                routing::post(create_zone_token_policy),
            )
            .route(
                "/zones/{name}/token-policies/{id}",
                routing::delete(delete_zone_token_policy),
            )
    }
}

#[derive(Deserialize)]
pub(crate) struct ZoneNameParam {
    pub name: String,
}

#[derive(Deserialize)]
pub(crate) struct ZoneTokenPolicyParam {
    pub name: String,
    pub id: i32,
}

#[utoipa::path(
        get,
        path = "/zones/{name}/token-policies",
        tag = "Token",
        summary = "List a zone's API token policies",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The zone's token policies", body = ZoneTokenPolicyListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List a zone's API token policies.
pub(crate) async fn get_zone_token_policies(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    caller.require_global("manage token policies")?;

    let policies = ZoneTokenPolicyService::list(&params.name).await?;
    let policies: Vec<GetZoneTokenPolicyResponse> = policies
        .iter()
        .map(GetZoneTokenPolicyResponse::from_policy)
        .collect();
    let json_body = json!({ "token_policies": policies });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/token-policies",
        tag = "Token",
        summary = "Grant an API token record rights in a zone",
        description = "Creates a token policy granting the token record-plane rights in the zone, optionally restricted by record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record types (`*` or a comma-separated list). Global tokens are rejected: they already cover every zone and never carry policies.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = CreateZoneTokenPolicyRequest,
        responses(
            (status = 201, description = "Token policy created", body = ZoneTokenPolicyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or token not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Grant an API token record rights in a zone.
pub(crate) async fn create_zone_token_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<CreateZoneTokenPolicyRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("manage token policies")?;

    let policy = ZoneTokenPolicyService::add(
        &params.name,
        &body.api_token,
        body.record_name_pattern.as_deref(),
        body.record_types.as_deref(),
    )
    .await?;
    let json_body = json!({ "token_policy": GetZoneTokenPolicyResponse::from_policy(&policy) });
    Ok((StatusCode::CREATED, Json(json_body)).into_response())
}

#[utoipa::path(
        delete,
        path = "/zones/{name}/token-policies/{id}",
        tag = "Token",
        summary = "Remove a token policy from a zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("id" = i32, Path, description = "The id of the token policy to remove.")
        ),
        responses(
            (status = 200, description = "Token policy deleted", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or policy not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Remove one token policy of a zone by policy id.
pub(crate) async fn delete_zone_token_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneTokenPolicyParam>,
) -> Result<Response, ApiError> {
    caller.require_global("manage token policies")?;

    ZoneTokenPolicyService::remove(&params.name, params.id).await?;
    let json_body = json!({ "message": "Token policy deleted successfully" });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}
