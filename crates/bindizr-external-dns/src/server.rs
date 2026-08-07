//! The webhook listener (external-dns side) and the health/metrics listener.

use std::{sync::Arc, time::Instant};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing,
};
use bindizr_core::{log_info, log_warn};

use crate::{
    metrics::{TEXT_CONTENT_TYPE, metrics},
    upstream::{UpstreamClient, UpstreamError},
    wire::{
        Changes, DomainFilter, Endpoint, MEDIA_TYPE, adjust_endpoints,
        group_records_into_endpoints, to_bindizr_changes,
    },
};

pub(crate) struct AppState {
    pub upstream: UpstreamClient,
}

/// Build the webhook router served on the (localhost) provider listener.
pub(crate) fn webhook_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", routing::get(negotiate))
        .route("/records", routing::get(get_records).post(apply_changes))
        .route("/adjustendpoints", routing::post(adjust_endpoints_handler))
        .with_state(state)
}

/// Build the health/metrics router served on the exposed listener.
pub(crate) fn health_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", routing::get(healthz))
        .route("/metrics", routing::get(get_metrics))
        .with_state(state)
}

/// external-dns fails hard on a mismatched negotiation Content-Type, so every
/// webhook response carries the exact media-type string.
fn webhook_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, MEDIA_TYPE)], body).into_response()
}

fn json_response<T: serde::Serialize>(value: &T) -> Response {
    match serde_json::to_string(value) {
        Ok(body) => webhook_response(StatusCode::OK, body),
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

fn track(endpoint: &'static str, started: Instant, response: Response) -> Response {
    metrics()
        .requests_total
        .with_label_values(&[endpoint, result_label(&response)])
        .inc();
    metrics()
        .request_duration_seconds
        .with_label_values(&[endpoint])
        .observe(started.elapsed().as_secs_f64());
    response
}

/// `GET /` — negotiation: return the DomainFilter of manageable zones.
async fn negotiate(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let started = Instant::now();

    if !accept_is_supported(&headers) {
        return track(
            "negotiate",
            started,
            (
                StatusCode::NOT_ACCEPTABLE,
                format!("supported media type: {}", MEDIA_TYPE),
            )
                .into_response(),
        );
    }

    let response = match state.upstream.get_zones().await {
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
    };
    track("negotiate", started, response)
}

/// `GET /records` — all managed records as grouped endpoints.
async fn get_records(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let started = Instant::now();

    if !accept_is_supported(&headers) {
        return track(
            "records_get",
            started,
            (
                StatusCode::NOT_ACCEPTABLE,
                format!("supported media type: {}", MEDIA_TYPE),
            )
                .into_response(),
        );
    }

    let response = match state.upstream.get_records().await {
        Ok(records) => {
            let endpoints = group_records_into_endpoints(records);
            log_info!("event=records_get endpoints={}", endpoints.len());
            json_response(&endpoints)
        }
        Err(e) => upstream_error_response(e),
    };
    track("records_get", started, response)
}

/// `POST /records` — apply a plan.Changes set as one bindizr change set.
async fn apply_changes(State(state): State<Arc<AppState>>, body: String) -> Response {
    let started = Instant::now();

    let changes: Changes = match serde_json::from_str(&body) {
        Ok(changes) => changes,
        Err(e) => {
            return track(
                "records_apply",
                started,
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid changes body: {}", e),
                )
                    .into_response(),
            );
        }
    };

    let bindizr_changes = match to_bindizr_changes(&changes) {
        Ok(converted) => converted,
        Err(message) => {
            log_warn!("event=records_apply rejected={}", message);
            return track(
                "records_apply",
                started,
                (StatusCode::BAD_REQUEST, message).into_response(),
            );
        }
    };

    let response = match state.upstream.apply_changes(&bindizr_changes).await {
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
    };
    track("records_apply", started, response)
}

/// `POST /adjustendpoints` — validate and normalize desired endpoints.
async fn adjust_endpoints_handler(body: String) -> Response {
    let started = Instant::now();

    let endpoints: Vec<Endpoint> = match serde_json::from_str(&body) {
        Ok(endpoints) => endpoints,
        Err(e) => {
            return track(
                "adjustendpoints",
                started,
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid endpoints body: {}", e),
                )
                    .into_response(),
            );
        }
    };

    let response = match adjust_endpoints(endpoints) {
        Ok(adjusted) => json_response(&adjusted),
        Err(message) => {
            log_warn!("event=adjustendpoints rejected={}", message);
            (StatusCode::BAD_REQUEST, message).into_response()
        }
    };
    track("adjustendpoints", started, response)
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
