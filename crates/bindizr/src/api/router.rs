use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::{Extension, Json, Router, routing};
use bindizr_service::Context;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::MessageResponse;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use utoipa::OpenApi;

use super::error::ApiError;
use super::middleware::body_parser::DEFAULT_BODY_BYTES;
use super::openapi::ApiDoc;
use super::{
    audit, dnssec, dnssec_policy, external_dns, notify, permission, record, role, secondary, token,
    tsig_key, zone,
};

/// Build the full axum router with auth, CORS, and the optional route groups,
/// every handler reading the daemon's state through `State`.
pub(crate) fn routes(cx: Arc<Context>) -> Router {
    let config = cx.config();
    let api_config = &config.api;

    let mut api_router = Router::new()
        .merge(zone::routes())
        .merge(record::routes())
        .merge(notify::routes())
        .merge(secondary::routes())
        .merge(tsig_key::routes())
        .merge(token::routes())
        .merge(role::routes())
        .merge(permission::routes())
        .merge(dnssec::routes())
        .merge(dnssec_policy::routes())
        .merge(audit::routes())
        .route("/", routing::get(handle_home));

    // Unregistered when disabled, so the endpoints fall through to 404.
    if api_config.external_dns_enabled {
        api_router = api_router.merge(external_dns::routes());
    }

    if api_config.authentication_required {
        api_router = api_router.layer(axum::middleware::from_fn_with_state(
            cx.clone(),
            super::middleware::auth::auth_middleware,
        ));
    } else {
        // Attach the API caller explicitly so a missing caller stays a wiring
        // error the extractor rejects instead of implying full access.
        api_router = api_router.layer(Extension(Caller::unauthenticated_api()));
    }

    let mut router = api_router;

    // Outside the auth layer: probes must work without credentials.
    router = router.route("/health", routing::get(super::health::handle_health));

    // Also outside auth: scrapers get only aggregate counts, no zone data.
    if api_config.metrics_enabled {
        router = router.route("/metrics", routing::get(super::metrics::handle_metrics));
    }

    // Also outside auth: the document is the API's own description.
    if api_config.openapi_enabled {
        router = router
            .route("/openapi.json", routing::get(openapi_json))
            .route("/openapi.yaml", routing::get(openapi_yaml));
    } else {
        // A bare 404 reads as "no such endpoint" for a path the docs name.
        router = router
            .route("/openapi.json", routing::get(openapi_disabled))
            .route("/openapi.yaml", routing::get(openapi_disabled));
    }

    router = router
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed);

    // Layered after the fallback so every route, including 404s, is measured.
    if api_config.metrics_enabled {
        router = router.layer(axum::middleware::from_fn_with_state(
            cx.clone(),
            super::middleware::metrics::track_http_metrics,
        ));
    }

    // Preflights must name `Authorization` itself: the Fetch standard never lets
    // `*` stand for it, and any origin may call with a token.
    router = router.layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(AllowHeaders::mirror_request())
            .expose_headers(Any),
    );

    // The routes that take uploads raise their own limit above this one.
    router = router.layer(DefaultBodyLimit::max(DEFAULT_BODY_BYTES));

    router.with_state(cx)
}

/// Return the API's running-status message.
async fn handle_home() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(MessageResponse {
            message: "bindizr API running".to_string(),
        }),
    )
}

/// Return the OpenAPI document as JSON.
async fn openapi_json() -> impl IntoResponse {
    (StatusCode::OK, Json(ApiDoc::openapi()))
}

/// Return the OpenAPI document as YAML.
async fn openapi_yaml() -> axum::response::Response {
    match serde_norway::to_string(&ApiDoc::openapi()) {
        Ok(openapi_yaml) => (
            StatusCode::OK,
            [(CONTENT_TYPE, "application/yaml; charset=utf-8")],
            openapi_yaml,
        )
            .into_response(),
        Err(error) => ApiError(ServiceError::internal_with_source(
            "failed to generate OpenAPI YAML",
            error,
        ))
        .into_response(),
    }
}

/// Return the API error for an unsupported HTTP method.
async fn method_not_allowed() -> impl IntoResponse {
    ApiError(ServiceError::MethodNotAllowed(
        "this path does not take that method".to_string(),
    ))
}

/// Return the API error for the OpenAPI document while it is not served.
async fn openapi_disabled() -> impl IntoResponse {
    ApiError(ServiceError::EndpointNotFound(
        "the OpenAPI document is not served; set api.openapi_enabled = true to serve it"
            .to_string(),
    ))
}

/// Return the API error for an unknown route.
async fn not_found() -> impl IntoResponse {
    ApiError(ServiceError::EndpointNotFound(
        "no route matches this path".to_string(),
    ))
}
