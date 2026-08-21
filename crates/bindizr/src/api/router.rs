use axum::{
    Extension, Json, Router,
    http::{StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing,
};
use bindizr_core::config;
use bindizr_service::{authorization::Caller, error::ServiceError, types::MessageResponse};
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;

use super::{
    dnssec::DnssecApi, error::ApiError, external_dns::ExternalDnsApi, notify::NotifyApi,
    openapi::ApiDoc, record::RecordApi, token_policy::TokenPolicyApi, tsig_key::TsigKeyApi,
    zone::ZoneApi,
};

/// HTTP API router assembling all route groups.
pub(crate) struct ApiRouter;

impl ApiRouter {
    /// Build the full axum router with auth, CORS, and the optional route groups.
    pub(crate) async fn routes() -> Router {
        let api_config = &config::bindizr_config().api;

        let mut api_router = Router::new()
            .merge(ZoneApi::routes().await)
            .merge(RecordApi::routes().await)
            .merge(NotifyApi::routes().await)
            .merge(TsigKeyApi::routes().await)
            .merge(TokenPolicyApi::routes().await)
            .merge(DnssecApi::routes().await)
            .route("/", routing::get(ApiRouter::get_home));

        // Unregistered when disabled, so the endpoints fall through to 404.
        if api_config.external_dns_enabled {
            api_router = api_router.merge(ExternalDnsApi::routes().await);
        }

        if api_config.require_authentication {
            api_router = api_router.layer(axum::middleware::from_fn(
                super::middleware::auth::auth_middleware,
            ));
        } else {
            // Grant Global explicitly so a missing caller stays a wiring
            // error the extractor rejects instead of implying full access.
            api_router = api_router.layer(Extension(Caller::Global));
        }

        let mut router = api_router;

        // Outside the auth layer: probes must work without credentials.
        router = router.route("/health", routing::get(super::health::get_health));

        // Also outside auth: scrapers get only aggregate counts, no zone data.
        if api_config.metrics_enabled {
            router = router.route("/metrics", routing::get(super::metrics::get_metrics));
        }

        // Also outside auth: the document is the API's own description.
        if api_config.openapi_enabled {
            router = router
                .route("/openapi.json", routing::get(ApiRouter::openapi_json))
                .route("/openapi.yaml", routing::get(ApiRouter::openapi_yaml));
        }

        router = router.fallback(Self::not_found);

        // Layered after the fallback so every route, including 404s, is measured.
        if api_config.metrics_enabled {
            router = router.layer(axum::middleware::from_fn(
                super::middleware::metrics::track_http_metrics,
            ));
        }

        router = router.layer(CorsLayer::permissive());

        router
    }

    async fn get_home() -> impl IntoResponse {
        (
            StatusCode::OK,
            Json(MessageResponse {
                message: "bindizr API running".to_string(),
            }),
        )
    }

    async fn openapi_json() -> impl IntoResponse {
        (StatusCode::OK, Json(ApiDoc::openapi()))
    }

    async fn openapi_yaml() -> axum::response::Response {
        match ApiDoc::openapi().to_yaml() {
            Ok(openapi_yaml) => (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/yaml; charset=utf-8")],
                openapi_yaml,
            )
                .into_response(),
            Err(err) => ApiError(ServiceError::internal(format!(
                "failed to generate OpenAPI YAML: {err}"
            )))
            .into_response(),
        }
    }

    async fn not_found() -> impl IntoResponse {
        (StatusCode::NOT_FOUND, "404 Not Found")
    }
}
