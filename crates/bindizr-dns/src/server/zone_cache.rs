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
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
    service::{error::ServiceError, zone::ZoneService},
};

/// Cap on distinct zones held at once. Each entry holds a zone's full record
/// set, so this bounds worst-case memory while comfortably covering the active
/// working set of any realistic deployment.
const MAX_ENTRIES: usize = 1024;

/// Everything a full transfer serves for one zone: the user records and the
/// derived DNSSEC plane (empty for an unsigned zone).
#[derive(Clone)]
pub(crate) struct ZoneContent {
    pub(crate) records: Arc<Vec<Record>>,
    pub(crate) dnssec_records: Arc<Vec<DnssecRecord>>,
}

struct CachedZone {
    serial: i32,
    content: ZoneContent,
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

/// Load a zone's transfer content, from cache when enabled and fresh.
/// Serve the returned zone row, not the pre-read one — it is the row the
/// content was read with. `None` when the zone was deleted meanwhile.
pub(crate) async fn list_zone_content(
    zone: Zone,
) -> Result<Option<(Zone, ZoneContent)>, ServiceError> {
    if !config::bindizr_config().dns.zone_cache {
        return load_content(zone).await;
    }

    // Fast path: a cached entry at the current serial is still valid.
    if let Some(content) = lookup(zone.id, zone.serial) {
        return Ok(Some((zone, content)));
    }

    // Slow path: read and cache. Concurrent misses may load twice; both store
    // one serial's consistent data, so the result is still correct.
    let Some((zone, content)) = load_content(zone).await? else {
        return Ok(None);
    };
    store(zone.id, zone.serial, content.clone());
    Ok(Some((zone, content)))
}

async fn load_content(zone: Zone) -> Result<Option<(Zone, ZoneContent)>, ServiceError> {
    let Some((loaded, records, dnssec_records)) = ZoneService::transfer_content(zone.id).await?
    else {
        return Ok(None);
    };
    // A rename since the pre-read would serve the new apex under the old name.
    if loaded.name != zone.name {
        return Ok(None);
    }
    let zone = loaded;
    Ok(Some((
        zone,
        ZoneContent {
            records: Arc::new(records),
            dnssec_records: Arc::new(dnssec_records),
        },
    )))
}

/// The cache holds no invariant a panicking thread could leave broken, so a
/// poisoned lock is recovered rather than failing every later query.
fn locked_cache() -> std::sync::MutexGuard<'static, HashMap<i32, CachedZone>> {
    cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lookup(zone_id: i32, serial: i32) -> Option<ZoneContent> {
    let mut map = locked_cache();
    let entry = map
        .get_mut(&zone_id)
        .filter(|entry| entry.serial == serial)?;
    entry.last_used = tick();
    Some(entry.content.clone())
}

fn store(zone_id: i32, serial: i32, content: ZoneContent) {
    let mut map = locked_cache();
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
            content,
            last_used: tick(),
        },
    );
}
