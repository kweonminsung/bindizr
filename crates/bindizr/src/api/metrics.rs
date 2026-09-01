use std::time::Duration;

use axum::{
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use bindizr_core::{
    config::bindizr_config,
    metrics::{TEXT_CONTENT_TYPE, metrics},
    model::dnssec_key::DnssecKeyState,
};
use bindizr_service::{
    authorization::Caller, dnssec::DnssecService, error::ServiceError, record::RecordService,
    zone::ZoneService,
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
    let caller = Caller::Global;

    metrics
        .zones_total
        .set(ZoneService::count(&caller).await? as i64);
    metrics
        .records_total
        .set(RecordService::count(&caller).await? as i64);

    metrics
        .dnssec_zones_total
        .set(DnssecService::count_signed_zones(&caller).await? as i64);
    for state in [
        DnssecKeyState::Published,
        DnssecKeyState::Active,
        DnssecKeyState::Retired,
    ] {
        let count = DnssecService::count_keys_by_state(&caller, state).await?;
        metrics
            .dnssec_keys_total
            .with_label_values(&[state.as_str()])
            .set(count as i64);
    }
    // The same cutoff as the scheduler's re-sign scan, so a persistent
    // nonzero value means that scan is not keeping up.
    let cutoff = Utc::now()
        + chrono::Duration::days(i64::from(bindizr_config().dnssec.signature_refresh_days));
    metrics
        .dnssec_rrsigs_expiring_total
        .set(DnssecService::count_rrsigs_expiring_before(&caller, cutoff).await? as i64);

    Ok(())
}
