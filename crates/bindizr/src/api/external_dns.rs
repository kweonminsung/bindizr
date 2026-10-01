use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    Context, external_dns,
    types::{
        ErrorResponse, ExternalDnsAdjustRequest, ExternalDnsAdjustResponse,
        ExternalDnsChangesRequest, ExternalDnsChangesResponse, ExternalDnsDomainsResponse,
        ExternalDnsRecordsResponse,
    },
};

use crate::api::{
    RequestCaller,
    error::ApiError,
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
};

/// Build ExternalDNS routes, registered only when `api.external_dns_enabled` is set.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route(
            "/external-dns/domains",
            routing::get(list_external_dns_domains),
        )
        .route(
            "/external-dns/records",
            routing::get(list_external_dns_records),
        )
        .route(
            "/external-dns/changes",
            // A whole external-dns plan arrives in one request, so it gets
            // the same upload cap as bulk insert, not axum's 2 MiB default.
            routing::post(apply_external_dns_changes)
                .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
        .route(
            "/external-dns/adjust",
            // The whole desired set arrives at once; same cap as changes.
            routing::post(adjust_external_dns_records)
                .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
        )
}

/// List the names the ExternalDNS caller may manage.
#[utoipa::path(
        get,
        path = "/external-dns/domains",
        tag = "ExternalDNS",
        summary = "List the names ExternalDNS may manage",
        description = "The ExternalDNS domain filter the calling token's role comes to: every zone name with authentication disabled, otherwise one name per grant that creates or deletes records — the zone where the grant covers every name, the granted subtree where it does not. Each entry covers itself and everything under it, so a grant narrowed by record type or to one exact name reads wider here than it is.",
        responses(
            (status = 200, description = "Manageable names", body = ExternalDnsDomainsResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_external_dns_domains(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    let domains = external_dns::list_managed_domains(&cx, &caller).await?;
    Ok((StatusCode::OK, Json(ExternalDnsDomainsResponse { domains })).into_response())
}

/// List the records of every zone the ExternalDNS caller may manage.
#[utoipa::path(
        get,
        path = "/external-dns/records",
        tag = "ExternalDNS",
        summary = "List the records of every ExternalDNS-managed zone",
        description = "Records of every zone the calling token may manage, restricted to the supported record types (A, AAAA, CNAME, TXT): one record per name and type, with absolute owner names and sorted presentation-form values.",
        responses(
            (status = 200, description = "Records of the allowed zones", body = ExternalDnsRecordsResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_external_dns_records(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    let records = external_dns::list_records(&cx, &caller).await?;
    Ok((StatusCode::OK, Json(ExternalDnsRecordsResponse { records })).into_response())
}

/// Canonicalize desired records for the ExternalDNS adapter's adjust step.
#[utoipa::path(
        post,
        path = "/external-dns/adjust",
        tag = "ExternalDNS",
        summary = "Canonicalize desired records without applying them",
        description = "Backs the adapter's AdjustEndpoints step: returns each desired record in the canonical form applying it would store (uppercase type, sorted deduplicated presentation values), so external-dns compares desired state against the exact spelling GET /external-dns/records returns.",
        request_body = ExternalDnsAdjustRequest,
        responses(
            (status = 200, description = "Canonicalized records, in request order", body = ExternalDnsAdjustResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn adjust_external_dns_records(
    RequestCaller(_caller): RequestCaller,
    JsonBody(body): JsonBody<ExternalDnsAdjustRequest>,
) -> Result<Response, ApiError> {
    let response = external_dns::adjust_records(&body)?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Apply an ExternalDNS change set atomically across its target zones.
#[utoipa::path(
        post,
        path = "/external-dns/changes",
        tag = "ExternalDNS",
        summary = "Apply an ExternalDNS change set atomically",
        description = "Applies creates, updates, and deletes in one transaction. Idempotent operations resolve to no change; only zones with a remaining delta advance their serial (once per request) and record IXFR history.",
        request_body = ExternalDnsChangesRequest,
        responses(
            (status = 200, description = "Change set applied (or resolved to a no-op)", body = ExternalDnsChangesResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The token is not allowed to manage a target record", body = ErrorResponse),
            (status = 404, description = "No authoritative zone for a record name, or the token cannot see it", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn apply_external_dns_changes(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<ExternalDnsChangesRequest>,
) -> Result<Response, ApiError> {
    let response = external_dns::apply_changes(&cx, &caller, &body).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
