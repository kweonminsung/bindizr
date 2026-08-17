use std::time::Duration;

use axum::{Json, http::StatusCode, response::IntoResponse};
use bindizr_service::{types::HealthResponse, zone::ZoneService};

/// Orchestrator probes expect a prompt 503, not a hang on a wedged database.
const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[utoipa::path(
        get,
        path = "/health",
        tag = "Health",
        summary = "Health probe",
        description = "Runs a minimal database query and reports whether the API can serve requests. Unauthenticated, intended for load-balancer and orchestrator probes; deeper checks (DNS listener, secondary sync) belong to 'bindizr doctor'.",
        security(()),
        responses(
            (status = 200, description = "Service healthy", body = HealthResponse),
            (status = 503, description = "Service unhealthy", body = HealthResponse)
        )
)]
/// Minimal database round-trip, kept cheap and side-effect free because
/// probes run frequently.
pub(crate) async fn get_health() -> impl IntoResponse {
    match tokio::time::timeout(DB_PROBE_TIMEOUT, ZoneService::ping()).await {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "healthy".to_string(),
            }),
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unhealthy".to_string(),
            }),
        ),
    }
}
