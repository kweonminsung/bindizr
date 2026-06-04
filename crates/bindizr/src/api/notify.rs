use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;

use crate::{
    api::{
        error::ApiError,
        middleware::body_parser::JsonBody,
        types::{ErrorResponse, MessageResponse, NotifyZoneRequest},
    },
    dns,
};

pub(crate) struct NotifyApi;

impl NotifyApi {
    pub(crate) async fn routes() -> Router {
        Router::new().route("/notify/zones", routing::post(notify_zones))
    }
}

#[utoipa::path(
        post,
        path = "/notify/zones",
        tag = "Notify",
        summary = "Send DNS NOTIFY messages for a zone or all zones",
        request_body = NotifyZoneRequest,
        responses(
            (status = 200, description = "DNS NOTIFY sent successfully", body = MessageResponse),
            (status = 400, description = "Bad request, invalid input", body = ErrorResponse),
            (status = 401, description = "Unauthorized", body = ErrorResponse),
            (status = 404, description = "Zone not found", body = ErrorResponse),
            (status = 415, description = "Unsupported media type, expected JSON request body", body = ErrorResponse),
            (status = 500, description = "Internal server error", body = ErrorResponse)
        )
)]
pub(crate) async fn notify_zones(JsonBody(body): JsonBody<NotifyZoneRequest>) -> impl IntoResponse {
    match dns::xfr::notify::send_notify(body.zone_name.as_deref()).await {
        Ok(()) => {
            let message = match body.zone_name {
                Some(zone_name) => format!("NOTIFY sent successfully for zone: {}", zone_name),
                None => "NOTIFY sent successfully for all zones".to_string(),
            };
            (StatusCode::OK, Json(json!({ "message": message }))).into_response()
        }
        Err(dns::xfr::error::XfrError::ZoneNotFound(zone_name)) => {
            ApiError::NotFound(format!("Zone not found: {}", zone_name)).into_response()
        }
        Err(err) => ApiError::InternalServerError(err.to_string()).into_response(),
    }
}
