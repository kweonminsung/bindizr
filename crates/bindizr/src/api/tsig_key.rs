use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    tsig_key::{TsigKeyService, grant::TsigGrantService},
    types::{
        CreateTsigGrantRequest, CreateTsigKeyRequest, DEFAULT_PAGE_LIMIT, ErrorResponse,
        GetTsigGrantResponse, GetTsigKeyResponse, MessageResponse, PageFilter, PaginatedResponse,
        TsigGrantResponse, TsigKeyResponse,
    },
};
use serde::Deserialize;

use crate::api::{
    GrantIdParam, RequestCaller, ZoneNameParam,
    error::{ApiError, Path, Query},
    middleware::body_parser::JsonBody,
};

pub(crate) struct TsigKeyApi;

impl TsigKeyApi {
    /// Build the TSIG key API routes.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/tsig-keys", routing::get(list_tsig_keys))
            .route("/tsig-keys", routing::post(create_tsig_key))
            .route("/tsig-keys/{name}", routing::get(get_tsig_key))
            .route("/tsig-keys/{name}", routing::delete(delete_tsig_key))
            .route("/tsig-keys/{name}/grants", routing::get(list_tsig_grants))
            .route("/tsig-keys/{name}/grants", routing::post(create_tsig_grant))
            .route(
                "/tsig-keys/{name}/grants/{id}",
                routing::delete(delete_tsig_grant),
            )
            .route(
                "/zones/{name}/tsig-grants",
                routing::get(list_zone_tsig_grants),
            )
    }
}

#[derive(Deserialize)]
pub(crate) struct TsigKeyNameParam {
    pub(crate) name: String,
}

/// List all TSIG keys (secrets omitted).
#[utoipa::path(
        get,
        path = "/tsig-keys",
        tag = "TSIG",
        summary = "List all TSIG keys",
        params(PageFilter),
        description = "Lists every TSIG key without its secret. Fetch a single key to read the secret.",
        responses(
            (status = 200, description = "All TSIG keys", body = PaginatedResponse<GetTsigKeyResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_tsig_keys(
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TsigKeyService::list(&caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create a TSIG key, generating a secret unless one is imported.
#[utoipa::path(
        post,
        path = "/tsig-keys",
        tag = "TSIG",
        summary = "Create a TSIG key",
        description = "Creates a TSIG key. When `secret` is omitted a random secret is generated; when provided it must be valid base64 (imports an existing key). Setting `global` permits updates and transfers for every zone without grants. The response includes the secret.",
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
pub(crate) async fn create_tsig_key(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateTsigKeyRequest>,
) -> Result<Response, ApiError> {
    let key = TsigKeyService::create(
        &caller,
        &body.name,
        body.algorithm.as_deref(),
        body.secret.as_deref(),
        body.global,
    )
    .await?;
    let response = TsigKeyResponse::from_key(&key);
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Get one TSIG key by name, including its secret.
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
pub(crate) async fn get_tsig_key(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TsigKeyNameParam>,
) -> Result<Response, ApiError> {
    let key = TsigKeyService::get(&caller, &params.name).await?;
    let response = TsigKeyResponse::from_key(&key);
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a TSIG key that holds no grants.
#[utoipa::path(
        delete,
        path = "/tsig-keys/{name}",
        tag = "TSIG",
        summary = "Delete a TSIG key",
        description = "Deletes a TSIG key. Refused while it still holds grants.",
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        responses(
            (status = 200, description = "TSIG key deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "TSIG key not found", body = ErrorResponse),
            (status = 409, description = "TSIG key still holds grants", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_tsig_key(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TsigKeyNameParam>,
) -> Result<Response, ApiError> {
    TsigKeyService::delete(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "TSIG key deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List a TSIG key's grants.
#[utoipa::path(
        get,
        path = "/tsig-keys/{name}/grants",
        tag = "TSIG",
        summary = "List a TSIG key's grants",
        params(PageFilter),
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        responses(
            (status = 200, description = "The key's grants", body = PaginatedResponse<GetTsigGrantResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "TSIG key not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_tsig_grants(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TsigKeyNameParam>,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TsigGrantService::list_by_key(&caller, &params.name, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Grant a TSIG key update and transfer rights in a zone.
#[utoipa::path(
        post,
        path = "/tsig-keys/{name}/grants",
        tag = "TSIG",
        summary = "Grant a TSIG key update and transfer rights in a zone",
        description = "Grants update rights in the named zone, optionally restricted by record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record types (`*` or a comma-separated list). Unrestricted name/type grants also allow transfers; `can_write=false` grants transfers only. Global keys are rejected: they already cover every zone and never carry grants.",
        params(
            ("name" = String, Path, description = "The name of the TSIG key.")
        ),
        request_body = CreateTsigGrantRequest,
        responses(
            (status = 201, description = "TSIG grant created", body = TsigGrantResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "TSIG key or zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_tsig_grant(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<TsigKeyNameParam>,
    JsonBody(body): JsonBody<CreateTsigGrantRequest>,
) -> Result<Response, ApiError> {
    let grant = TsigGrantService::grant(
        &caller,
        &params.name,
        &body.zone_name,
        body.record_name_pattern.as_deref(),
        body.record_types.as_deref(),
        body.can_write,
    )
    .await?;
    let response = TsigGrantResponse {
        tsig_grant: GetTsigGrantResponse::from_grant(&grant),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Revoke one of a TSIG key's grants by grant id.
#[utoipa::path(
        delete,
        path = "/tsig-keys/{name}/grants/{id}",
        tag = "TSIG",
        summary = "Revoke one of a TSIG key's grants",
        params(
            ("name" = String, Path, description = "The name of the TSIG key."),
            ("id" = i32, Path, description = "The id of the grant to revoke.")
        ),
        responses(
            (status = 200, description = "TSIG grant revoked", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "TSIG key or grant not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_tsig_grant(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<GrantIdParam>,
) -> Result<Response, ApiError> {
    TsigGrantService::revoke(&caller, &params.name, params.id).await?;
    let response = MessageResponse {
        message: "TSIG grant revoked successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List the TSIG grants that apply to a zone.
#[utoipa::path(
        get,
        path = "/zones/{name}/tsig-grants",
        tag = "TSIG",
        summary = "List the TSIG grants that apply to a zone",
        params(PageFilter),
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "Grants covering the zone", body = PaginatedResponse<GetTsigGrantResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_zone_tsig_grants(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(mut page): Query<PageFilter>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = TsigGrantService::list_by_zone(&caller, &params.name, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
