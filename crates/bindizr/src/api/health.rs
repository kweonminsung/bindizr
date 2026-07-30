use axum::{Json, http::StatusCode, response::IntoResponse};
use bindizr_service::zone::ZoneService;

use super::types::HealthResponse;

#[utoipa::path(
        get,
        path = "/health",
        tag = "Health",
        summary = "Health probe",
        description = "Runs a minimal database query and reports whether the API can serve requests. Unauthenticated, intended for load-balancer and orchestrator probes; deeper checks (DNS listener, secondary sync) belong to 'bindizr doctor'.",
        responses(
            (status = 200, description = "Service healthy", body = HealthResponse),
            (status = 503, description = "Service unhealthy", body = HealthResponse)
        )
)]
/// Report whether the API can serve requests, backed by a minimal database
/// query. Kept cheap and side-effect free because probes run frequently.
pub(crate) async fn get_health() -> impl IntoResponse {
    match ZoneService::ping().await {
        Ok(_) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "healthy".to_string(),
            }),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unhealthy".to_string(),
            }),
        ),
    }
}
