use std::time::Duration;

use axum::{
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use bindizr_core::metrics::{TEXT_CONTENT_TYPE, metrics};
use bindizr_service::{
    authorization::Caller, error::ServiceError, record::RecordService, zone::ZoneService,
};

/// Same budget as /health: scrapes must not hang on a wedged database.
const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Prometheus text-format scrape endpoint.
pub(crate) async fn get_metrics() -> Response {
    let metrics = metrics();

    // A failed probe still serves the instrumentation counters; only
    // database_up drops to 0.
    match tokio::time::timeout(DB_PROBE_TIMEOUT, fetch_db_totals()).await {
        Ok(Ok((zones, records))) => {
            metrics.database_up.set(1);
            metrics.zones_total.set(zones as i64);
            metrics.records_total.set(records as i64);
        }
        _ => metrics.database_up.set(0),
    }

    (
        StatusCode::OK,
        [(CONTENT_TYPE, TEXT_CONTENT_TYPE)],
        metrics.encode(),
    )
        .into_response()
}

// Totals only, so count directly: a limit-1 page still orders the whole table.
async fn fetch_db_totals() -> Result<(u64, u64), ServiceError> {
    let zones = ZoneService::count(&Caller::Global).await?;
    let records = RecordService::count(&Caller::Global).await?;

    Ok((zones, records))
}
