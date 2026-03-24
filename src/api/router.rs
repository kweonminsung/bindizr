use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;
use tower_http::cors::CorsLayer;

use crate::config;

use super::{record::RecordApi, zone::ZoneApi};

pub struct ApiRouter;

impl ApiRouter {
    pub async fn routes() -> Router {
        let mut router = Router::new()
            .merge(ZoneApi::routes().await)
            .merge(RecordApi::routes().await)
            .route("/", routing::get(ApiRouter::get_home))
            .fallback(Self::not_found);

        if config::get_config::<bool>("api.require_authentication") {
            router = router.layer(axum::middleware::from_fn(
                super::middleware::auth::auth_middleware,
            ));
        }

        router = router.layer(CorsLayer::permissive());

        router
    }

    async fn get_home() -> impl IntoResponse {
        (
            StatusCode::OK,
            Json(json!({ "msg": "bindizr API running" })),
        )
    }

    async fn not_found() -> impl IntoResponse {
        (StatusCode::NOT_FOUND, "404 Not Found")
    }
}
