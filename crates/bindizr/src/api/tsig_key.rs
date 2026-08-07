use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{tsig_key::TsigKeyService, zone::tsig_policy::ZoneTsigPolicyService};
use serde::Deserialize;
use serde_json::json;

use crate::api::{
    RequestCaller,
    error::ApiError,
    middleware::body_parser::JsonBody,
    types::{
        CreateTsigKeyRequest, CreateZoneTsigPolicyRequest, ErrorResponse, GetTsigKeyResponse,
        GetZoneTsigPolicyResponse, MessageResponse, TsigKeyListResponse, TsigKeyResponse,
        ZoneTsigPolicyListResponse, ZoneTsigPolicyResponse,
    },
};

/// Route group for TSIG key and zone TSIG policy endpoints.
pub(crate) struct TsigKeyApi;

impl TsigKeyApi {
    /// Build the router for TSIG key and zone TSIG policy endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/tsig-keys", routing::get(get_tsig_keys))
            .route("/tsig-keys", routing::post(create_tsig_key))
            .route("/tsig-keys/{name}", routing::get(get_tsig_key))
            .route("/tsig-keys/{name}", routing::delete(delete_tsig_key))
            .route(
                "/zones/{name}/tsig-policies",
                routing::get(get_zone_tsig_policies),
            )
            .route(
                "/zones/{name}/tsig-policies",
                routing::post(create_zone_tsig_policy),
            )
            .route(
                "/zones/{name}/tsig-policies/{id}",
                routing::delete(delete_zone_tsig_policy),
            )
    }
}

#[derive(Deserialize)]
pub(crate) struct TsigKeyNameParam {
    pub name: String,
}

#[derive(Deserialize)]
pub(crate) struct ZoneNameParam {
    pub name: String,
}

#[derive(Deserialize)]
pub(crate) struct ZoneTsigPolicyParam {
    pub name: String,
    pub id: i32,
}

#[utoipa::path(
        get,
        path = "/tsig-keys",
        tag = "TSIG",
        summary = "List all TSIG keys",
        description = "Lists every TSIG key without its secret. Fetch a single key to read the secret.",
        responses(
            (status = 200, description = "All TSIG keys", body = TsigKeyListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List all TSIG keys (secrets omitted).
pub(crate) async fn get_tsig_keys(
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    let keys = TsigKeyService::list().await?;
    let keys: Vec<GetTsigKeyResponse> = keys.iter().map(GetTsigKeyResponse::from_key).collect();
    let json_body = json!({ "tsig_keys": keys });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}

#[utoipa::path(
        post,
        path = "/tsig-keys",
        tag = "TSIG",
        summary = "Create a TSIG key",
        description = "Creates a TSIG key. When `secret` is omitted a random secret is generated; when provided it must be valid base64 (imports an existing key). Setting `global` makes the key able to update every zone (all names, all types) without any policy — effectively write access to all DNS data, so use it sparingly. The response includes the secret.",
        request_body = CreateTsigKeyRequest,
        responses(
            (status = 201, description = "TSIG key created successfully", body = TsigKeyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 409, description = "A TSIG key with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a TSIG key, generating a secret unless one is imported.
pub(crate) async fn create_tsig_key(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateTsigKeyRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    let key = TsigKeyService::create(
        &body.name,
        body.algorithm.as_deref(),
        body.secret.as_deref(),
        body.global,
    )
    .await?;
    let key = GetTsigKeyResponse::from_key(&key);
    let json_body = json!({ "tsig_key": key });
    Ok((StatusCode::CREATED, Json(json_body)).into_response())
}

#[utoipa::path(
        get,
        path = "/tsig-keys/{name}",
        tag = "TSIG",
        summary = "Get a specific TSIG key",
        description = "Returns one TSIG key including its secret.",
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        responses(
            (status = 200, description = "The TSIG key", body = TsigKeyResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "TSIG key not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Get one TSIG key by name, including its secret.
pub(crate) async fn get_tsig_key(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TsigKeyNameParam>,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    let key = TsigKeyService::get(&params.name).await?;
    let key = GetTsigKeyResponse::from_key(&key);
    let json_body = json!({ "tsig_key": key });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}

#[utoipa::path(
        delete,
        path = "/tsig-keys/{name}",
        tag = "TSIG",
        summary = "Delete a TSIG key",
        description = "Deletes a TSIG key. Refused while any zone TSIG policy still references it.",
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        responses(
            (status = 200, description = "TSIG key deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "TSIG key not found", body = ErrorResponse),
            (status = 409, description = "TSIG key is still referenced by zone TSIG policies", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete a TSIG key that is not referenced by any policy.
pub(crate) async fn delete_tsig_key(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TsigKeyNameParam>,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    TsigKeyService::delete(&params.name).await?;
    let json_body = json!({ "message": "TSIG key deleted successfully" });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}

#[utoipa::path(
        get,
        path = "/zones/{name}/tsig-policies",
        tag = "TSIG",
        summary = "List a zone's TSIG policies",
        description = "Lists every TSIG policy of a zone: which keys may update which record names and types via nsupdate.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The zone's TSIG policies", body = ZoneTsigPolicyListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List all TSIG policies of a zone.
pub(crate) async fn get_zone_tsig_policies(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    let policies = ZoneTsigPolicyService::list(&params.name).await?;
    let policies: Vec<GetZoneTsigPolicyResponse> = policies
        .iter()
        .map(GetZoneTsigPolicyResponse::from_policy)
        .collect();
    let json_body = json!({ "tsig_policies": policies });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/tsig-policies",
        tag = "TSIG",
        summary = "Grant a TSIG key nsupdate rights in a zone",
        description = "Creates a TSIG policy granting the named key nsupdate rights in the zone, optionally restricted by record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record types (`*` or a comma-separated list). Global keys are rejected: they already cover every zone and never carry policies.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        request_body = CreateZoneTsigPolicyRequest,
        responses(
            (status = 201, description = "TSIG policy created successfully", body = ZoneTsigPolicyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or TSIG key not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a TSIG policy for a zone.
pub(crate) async fn create_zone_tsig_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    JsonBody(body): JsonBody<CreateZoneTsigPolicyRequest>,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    let policy = ZoneTsigPolicyService::add(
        &params.name,
        &body.tsig_key,
        body.record_name_pattern.as_deref(),
        body.record_types.as_deref(),
    )
    .await?;
    let policy = GetZoneTsigPolicyResponse::from_policy(&policy);
    let json_body = json!({ "tsig_policy": policy });
    Ok((StatusCode::CREATED, Json(json_body)).into_response())
}

#[utoipa::path(
        delete,
        path = "/zones/{name}/tsig-policies/{id}",
        tag = "TSIG",
        summary = "Remove a TSIG policy from a zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone."),
            ("id" = i32, Path, description = "The id of the TSIG policy.")
        ),
        responses(
            (status = 200, description = "TSIG policy deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone or TSIG policy not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete one TSIG policy of a zone.
pub(crate) async fn delete_zone_tsig_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneTsigPolicyParam>,
) -> Result<Response, ApiError> {
    caller.require_global("manage TSIG keys and policies")?;

    ZoneTsigPolicyService::remove(&params.name, params.id).await?;
    let json_body = json!({ "message": "TSIG policy deleted successfully" });
    Ok((StatusCode::OK, Json(json_body)).into_response())
}
