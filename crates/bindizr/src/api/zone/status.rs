//! HTTP status operations for managed zones.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bindizr_service::types::{ErrorResponse, ZoneStatusResponse};
use bindizr_service::{Context, zone};

use crate::api::RequestCaller;
use crate::api::error::{ApiError, Path};
use crate::params::NameParams;

/// Report the sync state of every enabled secondary for a zone.
#[utoipa::path(
        get,
        path = "/zones/{name}/status",
        tag = "Zone",
        summary = "Check how far each secondary has caught up with a zone",
        description = "Queries every enabled secondary for the SOA serial it currently serves and compares it with the zone's serial. Probes run live and in parallel; an unreachable secondary is reported with the failure reason. With no enabled secondaries the list is empty.",
        params(
            ("name" = String, Path, description = "The name of the DNS zone.")
        ),
        responses(
            (status = 200, description = "The zone's secondary sync status", body = ZoneStatusResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn get_zone_status(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
) -> Result<Response, ApiError> {
    let status = zone::get_status(&cx, &caller, &zone::normalize_name(&params.name)?).await?;
    Ok((StatusCode::OK, Json(status)).into_response())
}
