//! Per-zone cache of a zone's records, keyed by serial. Every write bumps the
//! serial, so an entry matching the zone's current serial is always fresh;
//! repeated AXFRs at that serial skip the database read. One entry per zone.
//!
//! The cache is bounded by the bytes it holds and evicts the least-recently-used
//! zone on overflow. A deleted zone has no invalidation hook here — the delete
//! path lives in `bindizr-service`, which this crate depends on, so it cannot
//! call back in without a dependency cycle — so without a bound the map would
//! retain every transferred-then-deleted zone's records for the life of the
//! process. An evicted zone simply re-reads from the database on its next
//! transfer.

use std::{
    collections::HashMap,
    mem::size_of,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use bindizr_core::{
    config,
    dns::name::OwnerName,
    metrics::metrics,
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
};
use bindizr_service::{error::ServiceError, zone::ZoneService};

/// Cap on the record bytes held at once, from `dns.zone_cache_max_mb`.
/// Counting entries would bound nothing: one large zone outweighs a thousand
/// small ones.
fn max_bytes() -> usize {
    config::bindizr_config().dns.zone_cache_max_mb as usize * 1024 * 1024
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
    bytes: usize,
    /// Logical clock value at last hit; drives LRU eviction.
    last_used: u64,
}

#[derive(Default)]
struct Cache {
    zones: HashMap<i32, CachedZone>,
    bytes: usize,
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
    let evicted = cache.store(zone_id, serial, content, max_bytes());
    let metrics = metrics();
    metrics.zone_cache_bytes.set(cache.bytes as i64);
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
        max_bytes: usize,
    ) -> usize {
        let bytes = content_bytes(&content);
        if bytes > max_bytes {
            return 0;
        }
        self.remove(zone_id);
        let mut evicted = 0;
        while self.bytes + bytes > max_bytes {
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
        self.bytes += bytes;
        self.zones.insert(
            zone_id,
            CachedZone {
                serial,
                content,
                bytes,
                last_used: tick(),
            },
        );
        evicted
    }

    fn remove(&mut self, zone_id: i32) {
        if let Some(removed) = self.zones.remove(&zone_id) {
            self.bytes -= removed.bytes;
        }
    }
}

/// What one zone's cached content costs on the heap: each row's struct plus
/// its variable-length fields, which are what a large zone grows.
fn content_bytes(content: &ZoneContent) -> usize {
    let records: usize = content
        .records
        .iter()
        .map(|record| size_of::<Record>() + owner_bytes(&record.name) + record.value.capacity())
        .sum();
    let dnssec_records: usize = content
        .dnssec_records
        .iter()
        .map(|record| {
            size_of::<DnssecRecord>()
                + owner_bytes(&record.name)
                + record.rdata.as_bytes().len()
                + record
                    .rrset_digest
                    .as_ref()
                    .map_or(0, |digest| digest.capacity())
        })
        .sum();
    records + dnssec_records
}

fn owner_bytes(name: &OwnerName) -> usize {
    name.labels()
        .iter()
        .map(|label| size_of::<String>() + label.capacity())
        .sum()
}

#[cfg(test)]
mod tests {
    use bindizr_core::{
        dns::name::OwnerName,
        model::record::{Record, RecordType},
    };
    use chrono::Utc;

    use super::{Cache, ZoneContent, content_bytes};

    const MAX_BYTES: usize = 64 * 1024 * 1024;

    fn zone_content(records: usize, value_len: usize) -> ZoneContent {
        let records = (0..records)
            .map(|i| Record {
                id: i as i32,
                name: OwnerName::from_row("www"),
                record_type: RecordType::TXT,
                value: "v".repeat(value_len),
                ttl: 3600,
                priority: None,
                created_at: Utc::now(),
                zone_id: 1,
            })
            .collect();
        ZoneContent {
            records: std::sync::Arc::new(records),
            dnssec_records: std::sync::Arc::new(Vec::new()),
        }
    }

    #[test]
    fn a_zone_larger_than_the_budget_is_served_uncached() {
        let mut cache = Cache::default();
        cache.store(1, 1, zone_content(1, MAX_BYTES + 1), MAX_BYTES);

        assert!(cache.lookup(1, 1).is_none());
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn a_second_large_zone_evicts_the_first_to_fit() {
        let mut cache = Cache::default();
        // A cap on entries would have held both, at 120% of the budget.
        cache.store(1, 1, zone_content(1, MAX_BYTES * 3 / 5), MAX_BYTES);
        cache.store(2, 1, zone_content(1, MAX_BYTES * 3 / 5), MAX_BYTES);

        assert!(cache.lookup(1, 1).is_none());
        assert!(cache.lookup(2, 1).is_some());
        assert!(cache.bytes <= MAX_BYTES);
    }

    #[test]
    fn eviction_drops_the_least_recently_used_zone() {
        let mut cache = Cache::default();
        cache.store(1, 1, zone_content(1, MAX_BYTES / 4), MAX_BYTES);
        cache.store(2, 1, zone_content(1, MAX_BYTES / 4), MAX_BYTES);
        assert!(cache.lookup(1, 1).is_some());

        // Fits only after one of the two is evicted, and zone 1 was just read.
        cache.store(3, 1, zone_content(1, MAX_BYTES / 2), MAX_BYTES);

        assert!(cache.lookup(2, 1).is_none());
        assert!(cache.lookup(1, 1).is_some());
        assert!(cache.lookup(3, 1).is_some());
    }

    #[test]
    fn restoring_a_zone_replaces_its_bytes_rather_than_adding_them() {
        let mut cache = Cache::default();
        let content = zone_content(4, 512);
        let bytes = content_bytes(&content);

        cache.store(1, 1, content.clone(), MAX_BYTES);
        cache.store(1, 2, content, MAX_BYTES);

        assert_eq!(cache.bytes, bytes);
        assert!(cache.lookup(1, 1).is_none());
        assert!(cache.lookup(1, 2).is_some());
    }
}
