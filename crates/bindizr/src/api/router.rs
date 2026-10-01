use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    http::{StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing,
};
use bindizr_service::{
    Context, authorization::Caller, error::ServiceError, types::MessageResponse,
};
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;

use super::{
    dnssec, dnssec_policy, error::ApiError, external_dns, notify, openapi::ApiDoc, record, role,
    secondary, token, tsig_key, zone,
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
        .merge(dnssec::routes())
        .merge(dnssec_policy::routes())
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

    router = router.layer(CorsLayer::permissive());

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
        Err(err) => ApiError(ServiceError::internal(format!(
            "failed to generate OpenAPI YAML: {err}"
        )))
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
