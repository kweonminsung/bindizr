mod dns;
mod middleware;
mod record;
mod record_history;
mod zone;
mod zone_history;

use axum::{http::StatusCode, response::IntoResponse, routing, Json, Router};
use serde_json::json;

use crate::config;

pub struct ApiController;

impl ApiController {
    pub async fn routes() -> Router {
        let mut router = Router::new()
            .merge(record_history::RecordHistoryController::routes().await)
            .merge(zone_history::ZoneHistoryController::routes().await)
            .merge(zone::ZoneController::routes().await)
            .merge(record::RecordController::routes().await)
            .merge(dns::DnsController::routes().await)
            .route("/", routing::get(ApiController::get_home))
            .fallback(Self::not_found);

        // Check if authentication is required
        if config::get_config::<bool>("api.require_authentication") {
            router = router.layer(axum::middleware::from_fn(middleware::auth::auth_middleware));
        }

        router
    }

    async fn get_home() -> impl IntoResponse {
        (StatusCode::OK, Json(json!({ "msg": "hello world!" })))
    }

    async fn not_found() -> impl IntoResponse {
        (StatusCode::NOT_FOUND, "Not Found")
    }
}
