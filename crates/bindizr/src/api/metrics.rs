use std::sync::Arc;

use axum::{
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use bindizr_core::metrics::TEXT_CONTENT_TYPE;
use bindizr_service::{Context, metrics::refresh_db_gauges};

use crate::daemon::db_probe::DB_PROBE_TIMEOUT;

/// Prometheus text-format scrape endpoint.
pub(crate) async fn handle_metrics(State(cx): State<Arc<Context>>) -> Response {
    let metrics = cx.metrics();

    // A failed probe still serves the instrumentation counters; only
    // database_up drops to 0.
    match tokio::time::timeout(DB_PROBE_TIMEOUT, refresh_db_gauges(&cx)).await {
        Ok(Ok(())) => metrics.database_up.set(1),
        _ => metrics.database_up.set(0),
    }

    (
        StatusCode::OK,
        [(CONTENT_TYPE, TEXT_CONTENT_TYPE)],
        metrics.encode(),
    )
        .into_response()
}
