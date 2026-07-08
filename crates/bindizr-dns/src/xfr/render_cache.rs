//! Per-zone cache of the rendered record set, keyed by serial.
//!
//! Every write bumps the zone serial, so a cached entry whose serial still
//! matches the zone's current serial is guaranteed to be up to date. Repeated
//! AXFRs at a stable serial — the common case once a burst of writes settles —
//! are then served from memory instead of re-reading every record from the
//! database. One entry per zone bounds memory to the live zone data.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::{
    config,
    model::record::Record,
    service::{error::ServiceError, record::RecordService},
};

struct CachedZone {
    serial: i32,
    records: Arc<Vec<Record>>,
}

static CACHE: OnceLock<Mutex<HashMap<i32, CachedZone>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<i32, CachedZone>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Load a zone's records for the given serial, using the render cache when
/// enabled. Falls back to a direct database read (uncached) when disabled.
pub(crate) async fn list_records(
    zone_id: i32,
    serial: i32,
) -> Result<Arc<Vec<Record>>, ServiceError> {
    if !config::get_bindizr_config().dns.render_cache {
        return Ok(Arc::new(RecordService::list_by_zone_id(zone_id).await?));
    }

    // Fast path: a cached entry at the current serial is still valid.
    if let Some(records) = lookup(zone_id, serial) {
        return Ok(records);
    }

    // Slow path: read and cache. Concurrent misses may load twice; both store
    // the same serial's data, so the result is still correct.
    let records = Arc::new(RecordService::list_by_zone_id(zone_id).await?);
    store(zone_id, serial, records.clone());
    Ok(records)
}

fn lookup(zone_id: i32, serial: i32) -> Option<Arc<Vec<Record>>> {
    let map = cache().lock().unwrap();
    map.get(&zone_id)
        .filter(|entry| entry.serial == serial)
        .map(|entry| entry.records.clone())
}

fn store(zone_id: i32, serial: i32, records: Arc<Vec<Record>>) {
    let mut map = cache().lock().unwrap();
    map.insert(zone_id, CachedZone { serial, records });
}
