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
    model::{dnssec_record::DnssecRecord, record::Record, tsig_key::TsigKey, zone::Zone},
};
use bindizr_service::{
    error::ServiceError,
    zone::{TransferAccess, TransferContent, ZoneService},
};

/// Read the configured cache record budget, which counts records rather than bytes.
fn max_records() -> usize {
    config::bindizr_config().dns.zone_cache_max_records as usize
}

/// Everything a full transfer serves for one zone: the user records and the
/// derived DNSSEC plane (empty for an unsigned zone).
#[derive(Clone)]
pub(crate) struct CachedTransferContent {
    pub(crate) records: Arc<Vec<Record>>,
    pub(crate) dnssec_records: Arc<Vec<DnssecRecord>>,
}

impl CachedTransferContent {
    /// Count user and derived records together, since a transfer serves both.
    fn record_count(&self) -> usize {
        self.records.len() + self.dnssec_records.len()
    }
}

struct CachedZone {
    serial: i32,
    content: CachedTransferContent,
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

/// The transfer content of the zone `zone_name` names, as far as `key`
/// may read it, from cache when enabled and fresh. The zone and the grant are
/// decided on one locked row; a hit serves the content of that row's serial.
pub(crate) async fn authorize_transfer_content_by_name(
    zone_name: &str,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<(Zone, CachedTransferContent)>, ServiceError> {
    if !config::bindizr_config().dns.zone_cache {
        return fetch_transfer_content(zone_name, key).await;
    }

    let zone = match ZoneService::authorize_transfer_by_name(zone_name, key).await? {
        TransferAccess::Granted(zone) => zone,
        TransferAccess::NotZone => return Ok(TransferAccess::NotZone),
        TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
    };
    if let Some(content) = find_cached_content(zone.id, zone.serial) {
        return Ok(TransferAccess::Granted((zone, content)));
    }

    // A miss reads under its own lock, deciding the zone and the grant there
    // again; concurrent misses may load twice, each one complete serial.
    let loaded = fetch_transfer_content(zone_name, key).await?;
    if let TransferAccess::Granted((zone, content)) = &loaded {
        store_content(zone.id, zone.serial, content.clone());
    }
    Ok(loaded)
}

/// Pull both record planes of the zone by name, as far as `key` may read
/// them, straight from the service.
async fn fetch_transfer_content(
    zone_name: &str,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<(Zone, CachedTransferContent)>, ServiceError> {
    Ok(
        ZoneService::authorize_transfer_content_by_name(zone_name, key)
            .await?
            .map(|content| {
                let TransferContent {
                    zone,
                    records,
                    dnssec_records,
                } = content;
                (
                    zone,
                    CachedTransferContent {
                        records: Arc::new(records),
                        dnssec_records: Arc::new(dnssec_records),
                    },
                )
            }),
    )
}

/// Lock the shared zone cache, recovering a poisoned lock because panics cannot leave a cache
/// invariant broken.
fn locked_cache() -> std::sync::MutexGuard<'static, Cache> {
    CACHE
        .get_or_init(|| Mutex::new(Cache::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Find cached zone content matching the requested serial, enforcing the
/// budget first: a reload can lower it, and a server that only serves cached
/// zones never stores again.
fn find_cached_content(zone_id: i32, serial: i32) -> Option<CachedTransferContent> {
    let mut cache = locked_cache();
    let evicted = cache.trim_to(max_records());
    if evicted > 0 {
        track_zone_cache_store(cache.records, evicted);
    }
    let content = cache.lookup(zone_id, serial);
    drop(cache);
    track_zone_cache_lookup(content.is_some());
    content
}

/// Store zone content in the cache within its configured budget.
fn store_content(zone_id: i32, serial: i32, content: CachedTransferContent) {
    let mut cache = locked_cache();
    let evicted = cache.store(zone_id, serial, content, max_records());
    track_zone_cache_store(cache.records, evicted);
}

impl Cache {
    /// Drop least-recently-used zones until the retained records fit
    /// `max_records`, which a reload may have lowered since the last store.
    fn trim_to(&mut self, max_records: usize) -> usize {
        let mut evicted = 0;
        while self.records > max_records {
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
        evicted
    }

    /// Find cached zone content matching the requested serial.
    fn lookup(&mut self, zone_id: i32, serial: i32) -> Option<CachedTransferContent> {
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
        content: CachedTransferContent,
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
