//! Zone transfer content cached by zone id and serial; record writes advance the serial.
//! The record budget bounds retained data, including entries for deleted zones.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use bindizr_core::{
    config,
    metrics::{track_zone_cache_lookup, track_zone_cache_store},
    model::{dnssec_record::DnssecRecord, record::Record, zone::Zone},
};
use bindizr_service::{error::ServiceError, zone::ZoneService};

/// Read the configured cache record budget, which counts records rather than bytes.
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

impl ZoneContent {
    /// Count user and derived records together, since a transfer serves both.
    fn record_count(&self) -> usize {
        self.records.len() + self.dnssec_records.len()
    }
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

/// Advance the logical clock used to track cache recency.
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

    if let Some(content) = lookup(zone.id, zone.serial) {
        return Ok(Some((zone, content)));
    }

    // Concurrent misses may load twice; each load still contains one complete serial.
    let Some((zone, content)) = load_content(zone).await? else {
        return Ok(None);
    };
    store(zone.id, zone.serial, content.clone());
    Ok(Some((zone, content)))
}

/// Load a consistent zone snapshot, rejecting a concurrent deletion or rename.
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

/// Lock the shared zone cache, recovering a poisoned lock because panics cannot leave a cache
/// invariant broken.
fn locked_cache() -> std::sync::MutexGuard<'static, Cache> {
    CACHE
        .get_or_init(|| Mutex::new(Cache::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Find cached zone content matching the requested serial.
fn lookup(zone_id: i32, serial: i32) -> Option<ZoneContent> {
    let content = locked_cache().lookup(zone_id, serial);
    track_zone_cache_lookup(content.is_some());
    content
}

/// Store zone content in the cache within its configured budget.
fn store(zone_id: i32, serial: i32, content: ZoneContent) {
    let mut cache = locked_cache();
    let evicted = cache.store(zone_id, serial, content, max_records());
    track_zone_cache_store(cache.records, evicted);
}

impl Cache {
    /// Find cached zone content matching the requested serial.
    fn lookup(&mut self, zone_id: i32, serial: i32) -> Option<ZoneContent> {
        let entry = self
            .zones
            .get_mut(&zone_id)
            .filter(|entry| entry.serial == serial)?;
        entry.last_used = tick();
        Some(entry.content.clone())
    }

    /// Store a zone within the record budget and return the number of evictions.
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

        let records = content.record_count();
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

    /// Remove a cached zone and subtract its records from the retained count.
    fn remove(&mut self, zone_id: i32) {
        if let Some(removed) = self.zones.remove(&zone_id) {
            self.records -= removed.records;
        }
    }
}

#[cfg(test)]
mod tests;
