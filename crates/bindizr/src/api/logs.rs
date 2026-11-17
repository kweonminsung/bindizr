//! The log endpoints: what Bindizr changed, served, and answered, read back
//! under `log:read`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use bindizr_service::types::{
    AccessLogFilter, AccessLogResponse, AuditLogFilter, AuditLogResponse, DEFAULT_PAGE_LIMIT,
    ErrorResponse, PaginatedResponse, TransferLogFilter, TransferLogResponse,
};
use bindizr_service::{Context, access, audit, transfer};

use crate::api::RequestCaller;
use crate::api::error::{ApiError, Query};

/// Build the log routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/logs/audit", routing::get(list_audit_logs))
        .route("/logs/access", routing::get(list_access_logs))
        .route("/logs/transfer", routing::get(list_transfer_logs))
}

/// List the audit log.
#[utoipa::path(
        get,
        path = "/logs/audit",
        tag = "Log",
        summary = "List the audit log",
        description = "The management changes, newest first: a token, role, grant, TSIG key, secondary or DNSSEC policy created, updated or deleted, and a zone deleted, each with the request path and the token that made it. Changes to zone data are in the zone's versions instead. Kept for `audit_log.max_days`. Needs `log:read` in all zones.",
        params(AuditLogFilter),
        responses(
            (status = 200, description = "The rows selected", body = PaginatedResponse<AuditLogResponse>),
            (status = 400, description = "Invalid query parameters", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_audit_logs(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut filter): Query<AuditLogFilter>,
) -> Result<Response, ApiError> {
    filter.limit = filter.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = audit::list(&cx, &caller, &filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List the access log.
#[utoipa::path(
        get,
        path = "/logs/access",
        tag = "Log",
        summary = "List the access log",
        description = "The management API requests and nsupdates Bindizr answered, newest first: the method and path or the zone, the client address, the token or TSIG key that verified, the status or RCODE, and the error. `denied` is HTTP 401 or 403, or an nsupdate whose TSIG was rejected or that was REFUSED; a zone the caller may not see answers 404 and is `failed`. No query string, body, token or secret is kept. `/health`, `/metrics`, the OpenAPI document and the daemon socket are not logged. Kept for `access_log.max_days`; `access_log.save = \"denied\"` keeps denials alone and `\"none\"` nothing. Needs `log:read` in all zones.",
        params(AccessLogFilter),
        responses(
            (status = 200, description = "The rows selected", body = PaginatedResponse<AccessLogResponse>),
            (status = 400, description = "Invalid query parameters", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_access_logs(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut filter): Query<AccessLogFilter>,
) -> Result<Response, ApiError> {
    filter.limit = filter.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = access::list(&cx, &caller, &filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// List the transfer log.
#[utoipa::path(
        get,
        path = "/logs/transfer",
        tag = "Log",
        summary = "List the transfer log",
        description = "The zone transfers Bindizr answered, refused, or failed, newest first, by client address and zone: AXFR, IXFR as a delta or as the whole zone, or why it was refused. A transfer of a zone Bindizr does not have leaves no row. `secondary_name` selects the addresses a secondary resolves to now. Kept for `transfer_log.max_days`, and each client's last transfer of each zone beyond that; `transfer_log.save = \"unserved\"` keeps refusals and failures alone and `\"none\"` nothing. Needs `log:read` in all zones.",
        params(TransferLogFilter),
        responses(
            (status = 200, description = "The rows selected", body = PaginatedResponse<TransferLogResponse>),
            (status = 400, description = "Invalid query parameters", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "The caller's role does not permit this", body = ErrorResponse),
            (status = 404, description = "Secondary not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn list_transfer_logs(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(mut filter): Query<TransferLogFilter>,
) -> Result<Response, ApiError> {
    filter.limit = filter.limit.or(Some(DEFAULT_PAGE_LIMIT));
    let response = transfer::list(&cx, &caller, &filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
