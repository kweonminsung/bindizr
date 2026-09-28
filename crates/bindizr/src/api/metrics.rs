use std::sync::Arc;

use axum::{
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use bindizr_core::{metrics::TEXT_CONTENT_TYPE, model::dnssec_key::DnssecKeyState};
use bindizr_service::{Context, dnssec, error::ServiceError, record, zone};
use chrono::Utc;

use crate::daemon::db_probe::DB_PROBE_TIMEOUT;

/// Prometheus text-format scrape endpoint.
pub(crate) async fn handle_metrics(State(cx): State<Arc<Context>>) -> Response {
    let metrics = cx.metrics();

    // A failed probe still serves the instrumentation counters; only
    // database_up drops to 0.
    match tokio::time::timeout(DB_PROBE_TIMEOUT, track_db_gauges(&cx)).await {
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

/// Set the database count and pool gauges for a metrics scrape.
///
/// Count directly: fetching even a one-record page still sorts the whole table.
async fn track_db_gauges(cx: &Context) -> Result<(), ServiceError> {
    let metrics = cx.metrics();

    // Run counts concurrently so the timeout budgets one round trip, not one per query.
    let (zones, records, dnssec_zones, published, active, retired, expiring, expired) = tokio::try_join!(
        zone::count_all(cx),
        record::count_all(cx),
        dnssec::count_signed_zones(cx),
        dnssec::count_keys_by_state(cx, DnssecKeyState::Published),
        dnssec::count_keys_by_state(cx, DnssecKeyState::Active),
        dnssec::count_keys_by_state(cx, DnssecKeyState::Retired),
        // Use the scheduler's per-policy refresh window so a persistent nonzero
        // count indicates that re-signing is not keeping up.
        dnssec::count_rrsigs_expiring_within_refresh(cx, Utc::now()),
        dnssec::count_rrsigs_expired(cx, Utc::now()),
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
    metrics.dnssec_rrsigs_expired_total.set(expired as i64);

    let pool = cx.db_stats();
    metrics.track_db_pool(pool.connections, pool.idle, pool.max);

    Ok(())
}
