use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::handler::Handler as _;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json, Router, middleware, routing};
use bindizr_service::Context;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::MessageResponse;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};

use crate::api::error::ApiError;
use crate::api::extract::DEFAULT_BODY_BYTES;
use crate::api::middleware::{access_log, auth};
use crate::api::{
    dnssec, dnssec_policy, external_dns, health, logs, metrics, notify, openapi, permission,
    record, role, secondary, token, tsig_key, zone,
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
        .merge(logs::routes())
        .route("/", routing::get(handle_home));

    // Unregistered when disabled, so the endpoints fall through to 404.
    if api_config.external_dns_enabled {
        api_router = api_router.merge(external_dns::routes());
    }

    if api_config.authentication_required {
        api_router = api_router.layer(middleware::from_fn_with_state(
            cx.clone(),
            auth::auth_middleware,
        ));
    } else {
        // Attach the API caller explicitly so a missing caller stays a wiring
        // error the extractor rejects instead of implying full access.
        api_router = api_router.layer(Extension(Caller::unauthenticated_api()));
    }

    // Outside the auth layer, so a request it refuses is saved too; the
    // probe, scrape and document routes below are not.
    api_router = api_router.layer(middleware::from_fn_with_state(
        cx.clone(),
        access_log::save_access_log,
    ));

    let mut router = api_router;

    // Outside the auth layer: probes must work without credentials.
    router = router.route("/health", routing::get(health::handle_health));

    // Also outside auth: scrapers get only aggregate counts, no zone data.
    if api_config.metrics_enabled {
        router = router.route("/metrics", routing::get(metrics::handle_metrics));
    }

    // Also outside auth: the document is the API's own description.
    if api_config.openapi_enabled {
        router = router
            .route("/openapi.json", routing::get(openapi::handle_openapi_json))
            .route("/openapi.yaml", routing::get(openapi::handle_openapi_yaml));
    } else {
        // A bare 404 reads as "no such endpoint" for a path the docs name.
        router = router
            .route(
                "/openapi.json",
                routing::get(openapi::handle_openapi_disabled),
            )
            .route(
                "/openapi.yaml",
                routing::get(openapi::handle_openapi_disabled),
            );
    }

    // The fallbacks answer outside the routes' layers, so they take the access
    // log themselves: a scan of unknown paths or methods is saved too.
    router = router
        .fallback(handle_not_found.layer(middleware::from_fn_with_state(
            cx.clone(),
            access_log::save_access_log,
        )))
        .method_not_allowed_fallback(handle_method_not_allowed.layer(
            middleware::from_fn_with_state(cx.clone(), access_log::save_access_log),
        ));

    // Layered after the fallback so every route, including 404s, is measured.
    if api_config.metrics_enabled {
        router = router.layer(middleware::from_fn_with_state(
            cx.clone(),
            crate::api::middleware::metrics::track_http_metrics,
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
async fn handle_home() -> Response {
    (
        StatusCode::OK,
        Json(MessageResponse {
            message: "bindizr API running".to_string(),
        }),
    )
        .into_response()
}

/// Return the API error for an unsupported HTTP method.
async fn handle_method_not_allowed() -> Response {
    ApiError(ServiceError::MethodNotAllowed {
        message: "this path does not take that method".to_string(),
    })
    .into_response()
}

/// Return the API error for an unknown route.
async fn handle_not_found() -> Response {
    ApiError(ServiceError::EndpointNotFound {
        message: "no route matches this path".to_string(),
    })
    .into_response()
}
