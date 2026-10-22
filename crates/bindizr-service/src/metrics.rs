//! Refresh instrumentation from the managed rows and the service's connection pool.

use bindizr_core::model::dnssec_key::DnssecKeyState;
use chrono::Utc;

use crate::{Context, dnssec, error::ServiceError, record, zone};

/// Set database count and pool gauges using direct counts to avoid sorting a listing.
pub async fn refresh_db_gauges(cx: &Context) -> Result<(), ServiceError> {
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
    metrics.set_db_pool_gauges(pool.connections, pool.idle, pool.max);

    Ok(())
}
