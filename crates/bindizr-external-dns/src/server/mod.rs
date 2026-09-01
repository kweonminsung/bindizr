//! The webhook listener (external-dns side) and the health/metrics listener.

use std::{sync::Arc, time::Instant};

use axum::{
    Router,
    extract::{DefaultBodyLimit, MatchedPath, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing,
};
use bindizr_core::{log_info, log_warn, metrics::TEXT_CONTENT_TYPE};

use crate::{
    metrics::metrics,
    upstream::{UpstreamClient, UpstreamError},
    wire::{
        Changes, DomainFilter, Endpoint, MEDIA_TYPE, group_records_into_endpoints,
        merge_adjusted_endpoints, to_bindizr_rrsets,
    },
};

pub(crate) struct AppState {
    pub(crate) upstream: UpstreamClient,
}

/// Whole-plan and whole-desired-set POSTs outgrow axum's 2 MiB default on
/// large initial reconciliations; matches the bindizr server's upload cap.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Build the webhook router served on the (localhost) provider listener.
pub(crate) fn webhook_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", routing::get(negotiate))
        .route("/records", routing::get(get_records).post(apply_changes))
        .route("/adjustendpoints", routing::post(adjust_endpoints_handler))
        .route_layer(middleware::from_fn(track_webhook_metrics))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Build the health/metrics router served on the exposed listener.
pub(crate) fn health_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", routing::get(healthz))
        .route("/metrics", routing::get(get_metrics))
        .with_state(state)
}

fn json_response<T: serde::Serialize>(value: &T) -> Response {
    match serde_json::to_string(value) {
        // external-dns compares the negotiation Content-Type byte-for-byte,
        // so success responses carry the exact media-type string.
        Ok(body) => (StatusCode::OK, [(header::CONTENT_TYPE, MEDIA_TYPE)], body).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to encode response: {}", e),
        )
            .into_response(),
    }
}

/// external-dns retries only 5xx; upstream 4xx pass through as permanent
/// errors and upstream 5xx / transport failures become a retryable 502.
fn upstream_error_response(error: UpstreamError) -> Response {
    match error {
        UpstreamError::Status { status, message } if status < 500 => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            message,
        )
            .into_response(),
        UpstreamError::Status { status, .. } => (
            StatusCode::BAD_GATEWAY,
            format!("bindizr responded with status {}", status),
        )
            .into_response(),
        UpstreamError::Unreachable(message) => (StatusCode::BAD_GATEWAY, message).into_response(),
    }
}

fn accept_is_supported(headers: &HeaderMap) -> bool {
    match headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        // external-dns always sends the exact media type; tolerate wildcard
        // and absent Accept for manual diagnostics.
        Some(accept) => accept.contains(MEDIA_TYPE) || accept.contains("*/*"),
        None => true,
    }
}

fn result_label(response: &Response) -> &'static str {
    match response.status() {
        status if status.is_success() => "ok",
        status if status.is_client_error() => "client_error",
        StatusCode::BAD_GATEWAY => "upstream_error",
        _ => "error",
    }
}

/// The endpoint label a route reports under (`metrics()` pre-registers these).
/// HEAD serves through `routing::get`; an unrouted method 405s, so `None`.
fn endpoint_label(method: &Method, route: &str) -> Option<&'static str> {
    match (method.as_str(), route) {
        ("GET" | "HEAD", "/") => Some("negotiate"),
        ("GET" | "HEAD", "/records") => Some("records_get"),
        ("POST", "/records") => Some("records_apply"),
        ("POST", "/adjustendpoints") => Some("adjustendpoints"),
        _ => None,
    }
}

/// Record request count and latency for the matched webhook route.
async fn track_webhook_metrics(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    let endpoint = endpoint_label(request.method(), &route);
    let started = Instant::now();

    let response = next.run(request).await;

    if let Some(endpoint) = endpoint {
        metrics()
            .requests_total
            .with_label_values(&[endpoint, result_label(&response)])
            .inc();
        metrics()
            .request_duration_seconds
            .with_label_values(&[endpoint])
            .observe(started.elapsed().as_secs_f64());
    }
    response
}

/// `GET /` — negotiation: return the DomainFilter of manageable zones.
async fn negotiate(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !accept_is_supported(&headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            format!("supported media type: {}", MEDIA_TYPE),
        )
            .into_response();
    }

    match state.upstream.get_zones().await {
        // An empty DomainFilter reads as "manage everything" to external-dns;
        // refuse retryably so a new grant heals negotiation without a restart.
        Ok(zones) if zones.is_empty() => (
            StatusCode::SERVICE_UNAVAILABLE,
            "no manageable zones: grant zones to the API token with \
             'bindizr zone token-policy add', or create a zone first",
        )
            .into_response(),
        Ok(zones) => {
            log_info!("event=negotiate zones={}", zones.len());
            json_response(&DomainFilter { include: zones })
        }
        Err(e) => upstream_error_response(e),
    }
}

/// `GET /records` — all managed records as grouped endpoints.
async fn get_records(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !accept_is_supported(&headers) {
        return (
            StatusCode::NOT_ACCEPTABLE,
            format!("supported media type: {}", MEDIA_TYPE),
        )
            .into_response();
    }

    match state.upstream.get_records().await {
        Ok(records) => {
            let endpoints = group_records_into_endpoints(records);
            log_info!("event=records_get endpoints={}", endpoints.len());
            json_response(&endpoints)
        }
        Err(e) => upstream_error_response(e),
    }
}

/// `POST /records` — apply a plan.Changes set as one bindizr change set.
async fn apply_changes(State(state): State<Arc<AppState>>, body: String) -> Response {
    let started = Instant::now();

    let changes: Changes = match serde_json::from_str(&body) {
        Ok(changes) => changes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid changes body: {}", e),
            )
                .into_response();
        }
    };

    let bindizr_changes = match changes.to_bindizr() {
        Ok(converted) => converted,
        Err(message) => {
            log_warn!("event=records_apply rejected={}", message);
            return (StatusCode::BAD_REQUEST, message).into_response();
        }
    };

    match state.upstream.apply_changes(&bindizr_changes).await {
        Ok(()) => {
            log_info!(
                "event=records_apply create={} update={} delete={} ms={:.1}",
                changes.create.len(),
                changes.update_new.len(),
                changes.delete.len(),
                started.elapsed().as_secs_f64() * 1000.0,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => upstream_error_response(e),
    }
}

/// `POST /adjustendpoints` — validate locally, canonicalize on the bindizr
/// server so this answer cannot drift from the stored form.
async fn adjust_endpoints_handler(State(state): State<Arc<AppState>>, body: String) -> Response {
    let endpoints: Vec<Endpoint> = match serde_json::from_str(&body) {
        Ok(endpoints) => endpoints,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid endpoints body: {}", e),
            )
                .into_response();
        }
    };

    let rrsets = match to_bindizr_rrsets(&endpoints) {
        Ok(rrsets) => rrsets,
        Err(message) => {
            log_warn!("event=adjustendpoints rejected={}", message);
            return (StatusCode::BAD_REQUEST, message).into_response();
        }
    };

    match state.upstream.adjust_rrsets(&rrsets).await {
        // A short answer would silently drop endpoints in the zip below.
        Ok(adjusted) if adjusted.len() != endpoints.len() => (
            StatusCode::BAD_GATEWAY,
            format!(
                "bindizr adjusted {} of {} rrsets",
                adjusted.len(),
                endpoints.len()
            ),
        )
            .into_response(),
        Ok(adjusted) => {
            log_info!("event=adjustendpoints endpoints={}", endpoints.len());
            json_response(&merge_adjusted_endpoints(endpoints, adjusted))
        }
        Err(e) => upstream_error_response(e),
    }
}

/// `GET /healthz` — this process is up and bindizr answers its
/// (unauthenticated) health endpoint.
async fn healthz(State(state): State<Arc<AppState>>) -> Response {
    match state.upstream.probe_health().await {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "bindizr unreachable").into_response(),
    }
}

/// `GET /metrics` — adapter-local Prometheus metrics.
async fn get_metrics() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, TEXT_CONTENT_TYPE)],
        metrics().encode(),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
