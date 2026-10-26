//! HTTP import operations for managed zones.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bindizr_service::types::{
    ErrorResponse, ImportZoneRequest, ImportZoneResponse, ImportZonesRequest, ImportZonesResponse,
};
use bindizr_service::{Context, zone};

use crate::api::RequestCaller;
use crate::api::error::{ApiError, Path};
use crate::api::middleware::body_parser::JsonBody;
use crate::params::NameParams;

/// Import records into a zone, reconciling them in one transaction.
#[utoipa::path(
        post,
        path = "/zones/{name}/import",
        tag = "Zone",
        summary = "Import records into a zone",
        description = "Reconcile records with the zone using append/upsert/replace, taken from BIND zone file text in `content` or transferred over AXFR from `from_server` (exactly one of the two; the source must allow the transfer). When applied, the zone serial is incremented once and a single NOTIFY is sent. If any record fails validation nothing is applied and the answer is 422, carrying the per-record errors. An unsupported record type rejects the whole import; no records are skipped to bypass validation. TTLs are decimal seconds as RFC 1035 defines them; a file using BIND's unit suffixes (`1h`) is refused — write it out in seconds first with `named-compilezone -o - <zone> <file>`.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to import records into.")
        ),
        request_body = ImportZoneRequest,
        responses(
            (status = 200, description = "Import summary", body = ImportZoneResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 409, description = "Record conflict", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 422, description = "The file was rejected and nothing was applied; the same body carries the per-record errors", body = ImportZoneResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn import_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    JsonBody(body): JsonBody<ImportZoneRequest>,
) -> Result<Response, ApiError> {
    let response = zone::import(&cx, &caller, &zone::normalize_name(&params.name)?, &body).await?;

    // A rejected file is a failed request, so a generic client does not read it
    // as an import; the body stays the same so the errors survive the status.
    let status = if response.was_rejected() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };

    Ok((status, Json(response)).into_response())
}

/// Import several zones from one server, each in its own transaction.
#[utoipa::path(
        post,
        path = "/import",
        tag = "Zone",
        summary = "Import zones from a server",
        description = "Pull the zones in `zone_names`, or the members of the server's catalog zone `from_catalog` (RFC 9432), over AXFR from `from_server`, and import each as `POST /zones/{name}/import` would, in its own transaction. The answer lists every zone's result (`ok`, `rejected`, `failed`) with its import answer or error; the request itself fails only when malformed, when the catalog cannot be read, or when `create` lacks `zone:create`, or a catalog the mode's record actions, in all zones.",
        request_body = ImportZonesRequest,
        responses(
            (status = 200, description = "One entry per zone, in the order imported", body = ImportZonesResponse),
            (status = 400, description = "Bad request, invalid input, or the catalog could not be transferred or read", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit creating zones", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn import_zones(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<ImportZonesRequest>,
) -> Result<Response, ApiError> {
    let response = zone::import_many(&cx, &caller, &body).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
