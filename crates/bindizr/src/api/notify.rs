use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    types::{ErrorResponse, MessageResponse, build_notify_message},
    zone::ZoneService,
};
use serde::Deserialize;

use crate::api::{
    RequestCaller, ZoneNameParam,
    error::{ApiError, Path, Query},
};

pub(crate) struct NotifyApi;

impl NotifyApi {
    pub(crate) async fn routes() -> Router {
        Router::new()
            .route("/notify", routing::post(notify_all_zones))
            .route("/zones/{name}/notify", routing::post(notify_zone))
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct NotifyQuery {
    bump_serial: Option<bool>,
}

#[utoipa::path(
        post,
        path = "/notify",
        tag = "Notify",
        summary = "Send DNS NOTIFY messages for all zones",
        params(
            ("bump_serial" = Option<bool>, Query, description = "Bump every zone's serial first, so secondaries transfer even when nothing changed.")
        ),
        responses(
            (status = 200, description = "DNS NOTIFY sent successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Send DNS NOTIFY messages for all zones.
pub(crate) async fn notify_all_zones(
    RequestCaller(caller): RequestCaller,
    Query(query): Query<NotifyQuery>,
) -> Result<Response, ApiError> {
    let bump_serial = query.bump_serial.unwrap_or(false);
    ZoneService::notify(&caller, None, bump_serial).await?;

    let response = MessageResponse {
        message: build_notify_message(None, bump_serial),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

#[utoipa::path(
        post,
        path = "/zones/{name}/notify",
        tag = "Notify",
        summary = "Send DNS NOTIFY messages for a zone",
        params(
            ("name" = String, Path, description = "The name of the DNS zone to notify secondaries about."),
            ("bump_serial" = Option<bool>, Query, description = "Bump the zone's serial first, so secondaries transfer even when nothing changed.")
        ),
        responses(
            (status = 200, description = "DNS NOTIFY sent successfully", body = MessageResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required to bump a serial or to notify the catalog zone", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Send DNS NOTIFY messages for one zone.
pub(crate) async fn notify_zone(
    RequestCaller(caller): RequestCaller,
    Path(params): Path<ZoneNameParam>,
    Query(query): Query<NotifyQuery>,
) -> Result<Response, ApiError> {
    let bump_serial = query.bump_serial.unwrap_or(false);
    ZoneService::notify(&caller, Some(&params.name), bump_serial).await?;

    let response = MessageResponse {
        message: build_notify_message(Some(&params.name), bump_serial),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
