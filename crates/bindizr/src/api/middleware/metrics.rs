use std::time::Instant;

use axum::{
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
use bindizr_core::metrics::metrics;

/// Record request count and latency, labeled by the route pattern
/// (`/zones/{zone_name}`, not the concrete path) to bound label cardinality.
pub(crate) async fn track_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());
    let started = Instant::now();

    let response = next.run(request).await;

    let metrics = metrics();
    metrics
        .http_requests_total
        .with_label_values(&[&method, &route, response.status().as_str()])
        .inc();
    metrics
        .http_request_duration_seconds
        .with_label_values(&[&method, &route])
        .observe(started.elapsed().as_secs_f64());

    response
}
