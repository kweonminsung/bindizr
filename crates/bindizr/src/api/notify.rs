use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing,
};
use bindizr_dns as dns;
use bindizr_service::{
    authorization,
    error::{ErrorCode, ServiceError},
    zone::ZoneService,
};
use serde_json::json;

use crate::api::{
    RequestCaller,
    error::ApiError,
    middleware::body_parser::JsonBody,
    types::{ErrorResponse, MessageResponse, NotifyZoneRequest},
};

/// Route group for NOTIFY endpoints.
pub(crate) struct NotifyApi;

impl NotifyApi {
    /// Build the router for NOTIFY endpoints.
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
            (status = 403, description = "A global API token is required to notify all zones", body = ErrorResponse),
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
    match &body.zone_name {
        Some(zone_name) => ZoneService::ensure_visible(&caller, zone_name).await?,
        None => authorization::require_global(&caller, "send NOTIFY for all zones")?,
    }

    match dns::client::notify::send_notify(body.zone_name.as_deref(), body.force).await {
        Ok(()) => {
            let message = match body.zone_name {
                Some(zone_name) if body.force => {
                    format!("NOTIFY sent successfully for zone: {} (forced)", zone_name)
                }
                Some(zone_name) => format!("NOTIFY sent successfully for zone: {}", zone_name),
                None if body.force => "NOTIFY sent successfully for all zones (forced)".to_string(),
                None => "NOTIFY sent successfully for all zones".to_string(),
            };
            Ok((StatusCode::OK, Json(json!({ "message": message }))).into_response())
        }
        Err(dns::error::XfrError::ZoneNotFound(zone_name)) => Err(ApiError(ServiceError::new(
            ErrorCode::ZoneNotFound,
            format!("Zone not found: {}", zone_name),
        ))),
        Err(err) => Err(ApiError(ServiceError::internal(err.to_string()))),
    }
}
