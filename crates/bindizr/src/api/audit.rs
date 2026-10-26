//! The audit log endpoint: the management changes, who made them, and when.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing};
use bindizr_service::types::{
    AuditLogFilter, AuditLogResponse, DEFAULT_PAGE_LIMIT, ErrorResponse, PaginatedResponse,
};
use bindizr_service::{Context, audit};

use crate::api::RequestCaller;
use crate::api::error::{ApiError, Query};

/// Build the audit log routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new().route("/audit", routing::get(list_audit_logs))
}

/// List the audit log.
#[utoipa::path(
    get,
    path = "/audit",
    tag = "Audit",
    summary = "List the audit log",
    description = "The management changes, newest first: a token, role, grant, TSIG key, secondary or DNSSEC policy created, updated or deleted, and a zone deleted, each with the request path and the token that made it. Changes to zone data are in the zone's versions instead. Needs `audit:read` in all zones.",
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
    let response = audit::list(&cx, &caller, filter).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
