use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    dnssec_policy::DnssecPolicyService,
    types::{
        CreateDnssecPolicyRequest, DnssecPolicyListResponse, DnssecPolicyResponse, ErrorResponse,
        GetDnssecPolicyResponse, MessageResponse, UpdateDnssecPolicyRequest,
    },
};
use serde::Deserialize;

use crate::api::{RequestCaller, error::ApiError, middleware::body_parser::JsonBody};

/// Route group for DNSSEC policy endpoints.
pub(crate) struct DnssecPolicyApi;

impl DnssecPolicyApi {
    /// Build the router for DNSSEC policy endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/dnssec-policies", routing::get(get_dnssec_policies))
            .route("/dnssec-policies", routing::post(create_dnssec_policy))
            .route("/dnssec-policies/{name}", routing::get(get_dnssec_policy))
            .route(
                "/dnssec-policies/{name}",
                routing::put(update_dnssec_policy),
            )
            .route(
                "/dnssec-policies/{name}",
                routing::delete(delete_dnssec_policy),
            )
    }
}

#[derive(Deserialize)]
pub(crate) struct DnssecPolicyNameParam {
    pub(crate) name: String,
}

#[utoipa::path(
        get,
        path = "/dnssec-policies",
        tag = "DNSSEC",
        summary = "List all DNSSEC policies",
        description = "Lists every DNSSEC policy: the named signing-parameter bundles zones sign under. A `default` policy (ECDSA P-256 CSK, NSEC, 14-day signatures re-signed with 5 days left) is seeded at startup.",
        responses(
            (status = 200, description = "All DNSSEC policies", body = DnssecPolicyListResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List all DNSSEC policies.
pub(crate) async fn get_dnssec_policies(
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    let policies = DnssecPolicyService::list(&caller).await?;
    let response = DnssecPolicyListResponse {
        dnssec_policies: policies
            .iter()
            .map(GetDnssecPolicyResponse::from_policy)
            .collect(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/dnssec-policies",
        tag = "DNSSEC",
        summary = "Create a DNSSEC policy",
        description = "Creates a DNSSEC policy. The algorithm (`ecdsap256sha256` by default; also `ecdsap384sha384`, `ed25519`, `ed448`, `rsasha256`, `rsasha512`), denial mode (`nsec` or `nsec3`), and key layout (`split_keys`) are fixed once created; the timing fields can be edited later. Omitted fields take the built-in defaults.",
        request_body = CreateDnssecPolicyRequest,
        responses(
            (status = 201, description = "DNSSEC policy created successfully", body = DnssecPolicyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 409, description = "A DNSSEC policy with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Create a DNSSEC policy.
pub(crate) async fn create_dnssec_policy(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateDnssecPolicyRequest>,
) -> Result<Response, ApiError> {
    let policy = DnssecPolicyService::create(&caller, body).await?;
    let response = DnssecPolicyResponse {
        dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

#[utoipa::path(
        get,
        path = "/dnssec-policies/{name}",
        tag = "DNSSEC",
        summary = "Get a specific DNSSEC policy",
        params(
            ("name" = String, Path, description = "The name of the DNSSEC policy.")
        ),
        responses(
            (status = 200, description = "The DNSSEC policy", body = DnssecPolicyResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "DNSSEC policy not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Get one DNSSEC policy by name.
pub(crate) async fn get_dnssec_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<DnssecPolicyNameParam>,
) -> Result<Response, ApiError> {
    let policy = DnssecPolicyService::get(&caller, &params.name).await?;
    let response = DnssecPolicyResponse {
        dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        put,
        path = "/dnssec-policies/{name}",
        tag = "DNSSEC",
        summary = "Edit a DNSSEC policy's timing",
        description = "Edits the policy's signature validity, re-sign threshold, scheduled ZSK lifetime, and rollover hold-downs; an omitted field keeps its value. The algorithm, denial mode, and key layout cannot change: move zones to another policy instead. Zones under the policy pick the new values up on their next signing pass or maintenance scan.",
        params(
            ("name" = String, Path, description = "The name of the DNSSEC policy.")
        ),
        request_body = UpdateDnssecPolicyRequest,
        responses(
            (status = 200, description = "DNSSEC policy updated", body = DnssecPolicyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "DNSSEC policy not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Edit a DNSSEC policy's timing fields.
pub(crate) async fn update_dnssec_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<DnssecPolicyNameParam>,
    JsonBody(body): JsonBody<UpdateDnssecPolicyRequest>,
) -> Result<Response, ApiError> {
    let policy = DnssecPolicyService::update(&caller, &params.name, body).await?;
    let response = DnssecPolicyResponse {
        dnssec_policy: GetDnssecPolicyResponse::from_policy(&policy),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        delete,
        path = "/dnssec-policies/{name}",
        tag = "DNSSEC",
        summary = "Delete a DNSSEC policy",
        description = "Deletes a DNSSEC policy. Refused while any zone signs under it.",
        params(
            ("name" = String, Path, description = "The name of the DNSSEC policy.")
        ),
        responses(
            (status = 200, description = "DNSSEC policy deleted successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 404, description = "DNSSEC policy not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC policy is still used by signed zones", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Delete a DNSSEC policy no zone signs under.
pub(crate) async fn delete_dnssec_policy(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<DnssecPolicyNameParam>,
) -> Result<Response, ApiError> {
    DnssecPolicyService::delete(&caller, &params.name).await?;
    let response = MessageResponse {
        message: "DNSSEC policy deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
