use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_service::{
    types::{ErrorResponse, MessageResponse, NotifyZoneRequest},
    zone::ZoneService,
};

use crate::api::{RequestCaller, error::ApiError, middleware::body_parser::JsonBody};

pub(crate) struct NotifyApi;

impl NotifyApi {
    pub(crate) async fn routes() -> Router {
        Router::new().route("/zones/notify", routing::post(notify_zones))
    }
}

#[utoipa::path(
        post,
        path = "/zones/notify",
        tag = "Notify",
        summary = "Send DNS NOTIFY messages for a zone or all zones",
        request_body = NotifyZoneRequest,
        responses(
            (status = 200, description = "DNS NOTIFY sent successfully", body = MessageResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 403, description = "A global API token is required to notify all zones or to bump a serial", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
/// Send DNS NOTIFY messages for a specific zone or all zones.
pub(crate) async fn notify_zones(
    RequestCaller(caller): RequestCaller,
    JsonBody(body): JsonBody<NotifyZoneRequest>,
) -> Result<Response, ApiError> {
    ZoneService::notify(&caller, body.zone_name.as_deref(), body.bump_serial).await?;

    let response = MessageResponse {
        message: body.success_message(),
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}
