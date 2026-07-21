//! Per-zone cache of the record set, keyed by serial. Every write bumps the
//! serial, so an entry matching the zone's current serial is always fresh;
//! repeated AXFRs at that serial skip the database read. One entry per zone.
//!
//! The cache is bounded (`MAX_ENTRIES`) and evicts the least-recently-used zone
//! on overflow. A deleted zone has no invalidation hook here — the delete path
//! lives in `bindizr-service`, which this crate depends on, so it cannot call
//! back in without a dependency cycle — so without a bound the map would retain
//! every transferred-then-deleted zone's records for the life of the process. An
//! evicted zone simply re-reads from the database on its next transfer.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    config,
    model::record::Record,
    service::{error::ServiceError, record::RecordService},
};

/// Cap on distinct zones held at once. Each entry holds a zone's full record
/// set, so this bounds worst-case memory while comfortably covering the active
/// working set of any realistic deployment.
const MAX_ENTRIES: usize = 1024;

struct CachedZone {
    serial: i32,
    records: Arc<Vec<Record>>,
    /// Logical clock value at last hit; drives LRU eviction.
    last_used: u64,
}

static CACHE: OnceLock<Mutex<HashMap<i32, CachedZone>>> = OnceLock::new();
static CLOCK: AtomicU64 = AtomicU64::new(0);

fn cache() -> &'static Mutex<HashMap<i32, CachedZone>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tick() -> u64 {
    CLOCK.fetch_add(1, Ordering::Relaxed)
}

/// Load a zone's records for `serial`, from cache when enabled and fresh.
pub(crate) async fn list_records(
    zone_id: i32,
    serial: i32,
) -> Result<Arc<Vec<Record>>, ServiceError> {
    if !config::get_bindizr_config().dns.zone_cache {
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
    let mut map = cache().lock().unwrap();
    let entry = map
        .get_mut(&zone_id)
        .filter(|entry| entry.serial == serial)?;
    entry.last_used = tick();
    Some(entry.records.clone())
}

fn store(zone_id: i32, serial: i32, records: Arc<Vec<Record>>) {
    let mut map = cache().lock().unwrap();
    // Evict the least-recently-used entry when inserting a new zone would exceed
    // the cap. Updating an existing zone (same key) never grows the map.
    if !map.contains_key(&zone_id) && map.len() >= MAX_ENTRIES {
        let lru_id = map
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(&id, _)| id);
        if let Some(id) = lru_id {
            map.remove(&id);
        }
    }
    map.insert(
        zone_id,
        CachedZone {
            serial,
            records,
            last_used: tick(),
        },
    );
}
