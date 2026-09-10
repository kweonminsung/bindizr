//! Per-zone cache of a zone's records, keyed by serial. Every write bumps the
//! serial, so an entry matching the zone's current serial is always fresh;
//! repeated AXFRs at that serial skip the database read. One entry per zone.
//!
//! The cache is bounded by the records it holds and evicts the
//! least-recently-used zone on overflow. A deleted zone has no invalidation hook here — the delete
//! path lives in `bindizr-service`, which this crate depends on, so it cannot
//! call back in without a dependency cycle — so without a bound the map would
//! retain every transferred-then-deleted zone's records for the life of the
//! process. An evicted zone simply re-reads from the database on its next
//! transfer.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use bindizr_core::{
    config,
    metrics::metrics,
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
};
use bindizr_service::{error::ServiceError, zone::ZoneService};

/// Cap on the records held at once, from `dns.zone_cache_max_records`.
/// Counting zones would bound nothing: one large zone outweighs a thousand
/// small ones. Records track memory within roughly an order of magnitude,
/// which is enough for a cache whose only failure is a database re-read.
fn max_records() -> usize {
    config::bindizr_config().dns.zone_cache_max_records as usize
}

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
    records: usize,
    /// Logical clock value at last hit; drives LRU eviction.
    last_used: u64,
}

#[derive(Default)]
struct Cache {
    zones: HashMap<i32, CachedZone>,
    records: usize,
}

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
static CLOCK: AtomicU64 = AtomicU64::new(0);

fn tick() -> u64 {
    CLOCK.fetch_add(1, Ordering::Relaxed)
}

/// Load a zone's transfer content, from cache when enabled and fresh.
/// Serve the returned zone row, not the pre-read one — it is the row the
/// content was read with. `None` when the zone was deleted meanwhile.
pub(crate) async fn find_zone_content(
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
    let Some((loaded, records, dnssec_records)) =
        ZoneService::find_transfer_content(zone.id).await?
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
fn locked_cache() -> std::sync::MutexGuard<'static, Cache> {
    CACHE
        .get_or_init(|| Mutex::new(Cache::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lookup(zone_id: i32, serial: i32) -> Option<ZoneContent> {
    let content = locked_cache().lookup(zone_id, serial);
    let result = if content.is_some() { "hit" } else { "miss" };
    metrics()
        .zone_cache_lookups_total
        .with_label_values(&[result])
        .inc();
    content
}

fn store(zone_id: i32, serial: i32, content: ZoneContent) {
    let mut cache = locked_cache();
    let evicted = cache.store(zone_id, serial, content, max_records());
    let metrics = metrics();
    metrics.zone_cache_records.set(cache.records as i64);
    metrics.zone_cache_evictions_total.inc_by(evicted as u64);
}

impl Cache {
    fn lookup(&mut self, zone_id: i32, serial: i32) -> Option<ZoneContent> {
        let entry = self
            .zones
            .get_mut(&zone_id)
            .filter(|entry| entry.serial == serial)?;
        entry.last_used = tick();
        Some(entry.content.clone())
    }

    /// Returns how many zones were evicted to make room.
    fn store(
        &mut self,
        zone_id: i32,
        serial: i32,
        content: ZoneContent,
        max_records: usize,
    ) -> usize {
        // Before the size check: a zone that grew past the budget must release
        // its old serial, which no lookup can satisfy any more.
        self.remove(zone_id);

        let records = content_records(&content);
        if records > max_records {
            return 0;
        }

        let mut evicted = 0;
        while self.records + records > max_records {
            let Some(lru_id) = self
                .zones
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(&id, _)| id)
            else {
                break;
            };
            self.remove(lru_id);
            evicted += 1;
        }

        self.records += records;
        self.zones.insert(
            zone_id,
            CachedZone {
                serial,
                content,
                records,
                last_used: tick(),
            },
        );

        evicted
    }

    fn remove(&mut self, zone_id: i32) {
        if let Some(removed) = self.zones.remove(&zone_id) {
            self.records -= removed.records;
        }
    }
}

/// Both planes, since a transfer serves both.
fn content_records(content: &ZoneContent) -> usize {
    content.records.len() + content.dnssec_records.len()
}

#[cfg(test)]
mod tests;
