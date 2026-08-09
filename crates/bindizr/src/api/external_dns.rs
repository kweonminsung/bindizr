use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    external_dns::ExternalDnsService,
    types::{
        ErrorResponse, ExternalDnsChangesRequest, ExternalDnsChangesResponse,
        ExternalDnsRecordsResponse, ExternalDnsZonesResponse,
    },
};
use serde_json::json;

use crate::api::{
    RequestCaller,
    error::ApiError,
    middleware::body_parser::{JsonBody, MAX_UPLOAD_BODY_BYTES},
};

/// Route group for the ExternalDNS provider endpoints, registered only when
/// `api.external_dns_enabled` is set.
pub(crate) struct ExternalDnsApi;

impl ExternalDnsApi {
    /// Build the router for ExternalDNS endpoints.
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/external-dns/zones", routing::get(get_external_dns_zones))
            .route(
                "/external-dns/records",
                routing::get(get_external_dns_records),
            )
            .route(
                "/external-dns/changes",
                // A whole external-dns plan arrives in one request, so it gets
                // the same upload cap as bulk insert, not axum's 2 MiB default.
                routing::post(apply_external_dns_changes)
                    .layer(DefaultBodyLimit::max(MAX_UPLOAD_BODY_BYTES)),
            )
    }
}

#[utoipa::path(
        get,
        path = "/external-dns/zones",
        tag = "ExternalDNS",
        summary = "List the zones ExternalDNS may manage",
        description = "Zones the calling token may manage: every zone for a global token, otherwise the zones granted through token policies.",
        responses(
            (status = 200, description = "Allowed zones", body = ExternalDnsZonesResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List the zones the ExternalDNS caller may manage.
pub(crate) async fn get_external_dns_zones(
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    let zones = ExternalDnsService::list_zones(&caller).await?;
    Ok((StatusCode::OK, Json(json!({ "zones": zones }))).into_response())
}

#[utoipa::path(
        get,
        path = "/external-dns/records",
        tag = "ExternalDNS",
        summary = "List the records of every ExternalDNS-managed zone",
        description = "Records of every zone the calling token may manage, restricted to the supported record types (A, AAAA, CNAME, TXT), with absolute owner names and presentation-form values.",
        responses(
            (status = 200, description = "Records of the allowed zones", body = ExternalDnsRecordsResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// List the records of every zone the ExternalDNS caller may manage.
pub(crate) async fn get_external_dns_records(
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    let records = ExternalDnsService::list_records(&caller).await?;
    Ok((StatusCode::OK, Json(json!({ "records": records }))).into_response())
}

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
            (status = 404, description = "No authoritative zone for a record name", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Apply an ExternalDNS change set atomically across its target zones.
pub(crate) async fn apply_external_dns_changes(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<ExternalDnsChangesRequest>,
) -> Result<Response, ApiError> {
    let response = ExternalDnsService::apply_changes(&body, &caller).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
