use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    Context, permission,
    types::{ErrorResponse, PermissionsResponse},
};

use crate::api::{RequestCaller, error::ApiError};

/// Build the permission API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new().route("/permissions", routing::get(get_permissions))
}

/// Report what the request's caller may do.
#[utoipa::path(
        get,
        path = "/permissions",
        tag = "Role",
        summary = "Get the caller's permissions",
        description = "What the calling token's role permits, computed from its grants: the actions held in all zones, including zones created later, and per zone where a zone-scoped grant adds to them. `whole_zone` lists the record actions held with no name or type limit, as export, versions, diffs, import and rollback need. With authentication disabled every action is permitted everywhere.",
        responses(
            (status = 200, description = "The caller's permissions", body = PermissionsResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_permissions(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
) -> Result<Response, ApiError> {
    let response = permission::get(&cx, &caller).await?;
    Ok((StatusCode::OK, Json(response)).into_response())
}
