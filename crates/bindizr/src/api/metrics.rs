use std::time::Duration;

use axum::{
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use bindizr_core::{
    metrics::{TEXT_CONTENT_TYPE, metrics},
    model::dnssec_key::DnssecKeyState,
};
use bindizr_service::{
    dnssec::DnssecService, error::ServiceError, record::RecordService, zone::ZoneService,
};
use chrono::Utc;

/// Same budget as /health: scrapes must not hang on a wedged database.
const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Prometheus text-format scrape endpoint.
pub(crate) async fn get_metrics() -> Response {
    let metrics = metrics();

    // A failed probe still serves the instrumentation counters; only
    // database_up drops to 0.
    match tokio::time::timeout(DB_PROBE_TIMEOUT, refresh_db_gauges()).await {
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

// Totals only, so count directly: a limit-1 page still orders the whole table.
async fn refresh_db_gauges() -> Result<(), ServiceError> {
    let metrics = metrics();

    // The same per-policy window as the scheduler's re-sign scan, so a
    // persistent nonzero value means that scan is not keeping up.
    // Concurrent, so the probe timeout budgets one round trip, not seven.
    let (zones, records, dnssec_zones, published, active, retired, expiring) = tokio::try_join!(
        ZoneService::count_all(),
        RecordService::count_all(),
        DnssecService::count_signed_zones(),
        DnssecService::count_keys_by_state(DnssecKeyState::Published),
        DnssecService::count_keys_by_state(DnssecKeyState::Active),
        DnssecService::count_keys_by_state(DnssecKeyState::Retired),
        DnssecService::count_rrsigs_expiring_within_refresh(Utc::now()),
    )?;

    metrics.zones_total.set(zones as i64);
    metrics.records_total.set(records as i64);
    metrics.dnssec_zones_total.set(dnssec_zones as i64);
    for (state, count) in [
        (DnssecKeyState::Published, published),
        (DnssecKeyState::Active, active),
        (DnssecKeyState::Retired, retired),
    ] {
        metrics
            .dnssec_keys_total
            .with_label_values(&[state.as_str()])
            .set(count as i64);
    }
    metrics.dnssec_rrsigs_expiring_total.set(expiring as i64);

    Ok(())
}
