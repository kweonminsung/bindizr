use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    Context,
    notify::NotifyTarget,
    types::{ErrorResponse, MessageResponse, NotifySerial, build_notify_message},
    zone,
};
use serde::Deserialize;

use crate::{
    api::{
        RequestCaller,
        error::{ApiError, Path, Query},
    },
    params::NameParams,
};

/// Build the notify API routes.
pub(crate) fn routes() -> Router<Arc<Context>> {
    Router::new()
        .route("/notify", routing::post(notify_all_zones))
        .route("/zones/{name}/notify", routing::post(notify_zone))
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotifyQuery {
    bump_serial: Option<bool>,
}

/// Send DNS NOTIFY messages for all zones.
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
pub(crate) async fn notify_all_zones(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Query(query): Query<NotifyQuery>,
) -> Result<Response, ApiError> {
    let serial = NotifySerial::from_bump_serial(query.bump_serial.unwrap_or(false));
    zone::notify(&cx, &caller, NotifyTarget::All, serial).await?;
    let response = MessageResponse {
        message: build_notify_message(NotifyTarget::All, serial),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

/// Send DNS NOTIFY messages for one zone.
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
pub(crate) async fn notify_zone(
    State(cx): State<Arc<Context>>,
    RequestCaller(caller): RequestCaller,
    Path(params): Path<NameParams>,
    Query(query): Query<NotifyQuery>,
) -> Result<Response, ApiError> {
    let serial = NotifySerial::from_bump_serial(query.bump_serial.unwrap_or(false));
    let target = NotifyTarget::Zone(&zone::normalize_name(&params.name)?);
    zone::notify(&cx, &caller, target, serial).await?;
    let response = MessageResponse {
        message: build_notify_message(target, serial),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
