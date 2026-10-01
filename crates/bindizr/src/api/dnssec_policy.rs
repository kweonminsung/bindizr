use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    Context, dnssec_policy,
    types::{
        CreateDnssecPolicyRequest, DEFAULT_PAGE_LIMIT, DnssecPolicyResponse, ErrorResponse,
        GetDnssecPolicyResponse, MessageResponse, PageRequest, PaginatedResponse,
        UpdateDnssecPolicyRequest,
    },
};

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
        middleware::body_parser::JsonBody,
    },
    params::NameParams,
};

/// Build the DNSSEC policy API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/dnssec-policies", routing::get(list_dnssec_policies))
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

/// List all DNSSEC policies.
#[utoipa::path(
        get,
        path = "/dnssec-policies",
        tag = "DNSSEC",
        summary = "List all DNSSEC policies",
        params(PageRequest),
        description = "Lists every DNSSEC policy: the named signing-parameter bundles zones sign under. A `default` policy (ECDSA P-256 CSK, NSEC, 14-day signatures re-signed with 5 days left) is seeded at startup.",
        responses(
            (status = 200, description = "All DNSSEC policies", body = PaginatedResponse<GetDnssecPolicyResponse>),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_dnssec_policies(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut page): Query<PageRequest>,
) -> Result<Response, ApiError> {
    page.limit = page.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = dnssec_policy::list(&cx, &caller, page).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Create a DNSSEC policy.
#[utoipa::path(
        post,
        path = "/dnssec-policies",
        tag = "DNSSEC",
        summary = "Create a DNSSEC policy",
        description = "Creates a DNSSEC policy. The algorithm (`ecdsap256sha256` by default; also `ecdsap384sha384`, `ed25519`, `ed448`, `rsasha256`, `rsasha512`), denial mode (`nsec3` by default, or `nsec`), and key layout (`split_keys`) are fixed once created; the timing fields can be edited later. Omitted fields take the built-in defaults.",
        request_body = CreateDnssecPolicyRequest,
        responses(
            (status = 201, description = "DNSSEC policy created successfully", body = DnssecPolicyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 409, description = "A DNSSEC policy with the same name already exists", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn create_dnssec_policy(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<CreateDnssecPolicyRequest>,
) -> Result<Response, ApiError> {
    let policy = dnssec_policy::create(&cx, &caller, body).await?;
    let response = DnssecPolicyResponse {
        dnssec_policy: GetDnssecPolicyResponse::from(&policy),
    };
    Ok((StatusCode::CREATED, Json(response)).into_response())
}

/// Get one DNSSEC policy by name.
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
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "DNSSEC policy not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_dnssec_policy(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let policy = dnssec_policy::get(&cx, &caller, &params.name).await?;
    let response = DnssecPolicyResponse {
        dnssec_policy: GetDnssecPolicyResponse::from(&policy),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Edit a DNSSEC policy's timing fields.
#[utoipa::path(
        put,
        path = "/dnssec-policies/{name}",
        tag = "DNSSEC",
        summary = "Edit a DNSSEC policy's timing",
        description = "Edits the policy's signature validity, re-sign threshold, and scheduled ZSK lifetime; an omitted field keeps its value. The algorithm, denial mode, and key layout cannot change: move zones to another policy instead. Zones under the policy pick the new values up on their next signing pass or scheduler scan.",
        params(
            ("name" = String, Path, description = "The name of the DNSSEC policy.")
        ),
        request_body = UpdateDnssecPolicyRequest,
        responses(
            (status = 200, description = "DNSSEC policy updated", body = DnssecPolicyResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "DNSSEC policy not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn update_dnssec_policy(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    JsonBody(body): JsonBody<UpdateDnssecPolicyRequest>,
) -> Result<Response, ApiError> {
    let policy = dnssec_policy::update(&cx, &caller, &params.name, body).await?;
    let response = DnssecPolicyResponse {
        dnssec_policy: GetDnssecPolicyResponse::from(&policy),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Delete a DNSSEC policy no zone signs under.
#[utoipa::path(
        delete,
        path = "/dnssec-policies/{name}",
        tag = "DNSSEC",
        summary = "Delete a DNSSEC policy",
        description = "Deletes a DNSSEC policy. Refused for the built-in `default` policy and while any zone signs under it.",
        params(
            ("name" = String, Path, description = "The name of the DNSSEC policy.")
        ),
        responses(
            (status = 200, description = "DNSSEC policy deleted successfully", body = MessageResponse),
            (status = 400, description = "The built-in default policy cannot be deleted", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "DNSSEC policy not found", body = ErrorResponse),
            (status = 409, description = "DNSSEC policy is still used by signed zones", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn delete_dnssec_policy(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    dnssec_policy::delete(&cx, &caller, &params.name).await?;
    let response = MessageResponse {
        message: "DNSSEC policy deleted successfully".to_string(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
