#[cfg(debug_assertions)]
use axum::http::header::CONTENT_TYPE;
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing};
use serde_json::json;
use tower_http::cors::CorsLayer;
#[cfg(debug_assertions)]
use utoipa::OpenApi;

use crate::config;

#[cfg(debug_assertions)]
use super::openapi::ApiDoc;
use super::{notify::NotifyApi, record::RecordApi, zone::ZoneApi};

pub struct ApiRouter;

impl ApiRouter {
    pub async fn routes() -> Router {
        let mut api_router = Router::new()
            .merge(ZoneApi::routes().await)
            .merge(RecordApi::routes().await)
            .merge(NotifyApi::routes().await)
            .route("/", routing::get(ApiRouter::get_home));

        if config::get_bindizr_config().api.require_authentication {
            api_router = api_router.layer(axum::middleware::from_fn(
                super::middleware::auth::auth_middleware,
            ));
        }

        let mut router = Router::new().merge(api_router);

        #[cfg(debug_assertions)]
        {
            router = router
                .route("/openapi.json", routing::get(ApiRouter::openapi_json))
                .route("/openapi.yaml", routing::get(ApiRouter::openapi_yaml));
        }

        router = router.fallback(Self::not_found);
        router = router.layer(CorsLayer::permissive());

        router
    }

    async fn get_home() -> impl IntoResponse {
        (
            StatusCode::OK,
            Json(json!({ "msg": "bindizr API running" })),
        )
    }

    #[cfg(debug_assertions)]
    async fn openapi_json() -> impl IntoResponse {
        (StatusCode::OK, Json(ApiDoc::openapi()))
    }

    #[cfg(debug_assertions)]
    async fn openapi_yaml() -> axum::response::Response {
        match ApiDoc::openapi().to_yaml() {
            Ok(openapi_yaml) => (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/yaml; charset=utf-8")],
                openapi_yaml,
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("failed to generate OpenAPI YAML: {err}"),
                })),
            )
                .into_response(),
        }
    }

    async fn not_found() -> impl IntoResponse {
        (StatusCode::NOT_FOUND, "404 Not Found")
    }
}
