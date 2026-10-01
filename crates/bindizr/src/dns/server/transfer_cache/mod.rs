//! Zone transfer content cached by zone id and serial; record writes advance the serial.
//! The record budget bounds retained data, including entries for deleted zones.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use bindizr_core::{
    dns::{Serial, name::ZoneName},
    metrics::Metrics,
    model::{
        dnssec_record::DnssecRecord,
        record::Record,
        tsig_key::TsigKey,
        zone::{Zone, ZoneId},
    },
};
use bindizr_service::{
    Context,
    error::ServiceError,
    zone::{self, TransferAccess, TransferContent},
};

use super::DnsContext;

/// Read the configured cache record budget, which counts records rather than bytes.
fn max_records(dns_cx: &Context) -> usize {
    dns_cx.config().dns.transfer_cache.max_records as usize
}

/// Everything a full transfer serves for one zone: the user records and the
/// derived DNSSEC plane (empty for an unsigned zone).
#[derive(Debug, Clone)]
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

/// One zone's transfer as cached: the serial it was built at, its content,
/// and what the budget and the LRU order read.
#[derive(Debug, Clone)]
struct CachedTransfer {
    serial: Serial,
    content: CachedTransferContent,
    records: usize,
    /// Logical clock value at last hit; drives LRU eviction.
    last_used: u64,
}

/// The DNS front end's transfer cache: one cached transfer per zone, behind
/// one lock, within the record budget `dns.transfer_cache.max_records` sets.
#[derive(Debug, Default)]
pub(crate) struct TransferCache {
    entries: Mutex<Entries>,
}

/// What the lock guards: the cached transfers by zone id, their record total
/// against the budget, and the clock recency is measured on. Lock-free, so
/// the eviction rules are unit-tested as they are.
#[derive(Debug, Default)]
struct Entries {
    zones: HashMap<ZoneId, CachedTransfer>,
    records: usize,
    /// The logical clock recency is measured on; advanced under the lock.
    clock: u64,
}

impl TransferCache {
    /// An empty cache.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Lock the cache, recovering a poisoned lock because panics cannot leave
    /// a cache invariant broken.
    fn locked(&self) -> MutexGuard<'_, Entries> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The cached content at `serial`, after enforcing the budget: a reload
    /// can lower it, and a server that only serves cached zones never stores
    /// again.
    fn find_cached_content(
        &self,
        metrics: &Metrics,
        max_records: usize,
        zone_id: ZoneId,
        serial: Serial,
    ) -> Option<CachedTransferContent> {
        let mut entries = self.locked();
        let evicted = entries.trim_to(max_records);
        if evicted > 0 {
            metrics.track_zone_cache_store(entries.records, evicted);
        }
        let content = entries.find(zone_id, serial);
        drop(entries);
        metrics.track_zone_cache_lookup(content.is_some());
        content
    }

    /// Store zone content in the cache within its configured budget.
    fn store_content(
        &self,
        metrics: &Metrics,
        max_records: usize,
        zone_id: ZoneId,
        serial: Serial,
        content: CachedTransferContent,
    ) {
        let mut entries = self.locked();
        let evicted = entries.store(zone_id, serial, content, max_records);
        metrics.track_zone_cache_store(entries.records, evicted);
    }
}

/// The transfer content of the zone `zone_name` names, as far as `key`
/// may read it, from cache when one is configured and fresh. The zone and
/// the grant are decided on one locked row; a hit serves the content of
/// that row's serial.
pub(crate) async fn authorize_transfer_content_by_name(
    dns_cx: &DnsContext,
    zone_name: &ZoneName,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<(Zone, CachedTransferContent)>, ServiceError> {
    let cx = dns_cx.daemon();
    let max_records = max_records(cx);
    if max_records == 0 {
        return fetch_transfer_content(cx, zone_name, key).await;
    }

    let zone = match zone::authorize_transfer_by_name(cx, zone_name, key).await? {
        TransferAccess::Granted(zone) => zone,
        TransferAccess::NotAuth => return Ok(TransferAccess::NotAuth),
        TransferAccess::Refused(reason) => return Ok(TransferAccess::Refused(reason)),
    };
    if let Some(content) =
        dns_cx
            .transfer_cache
            .find_cached_content(cx.metrics(), max_records, zone.id, zone.serial)
    {
        return Ok(TransferAccess::Granted((zone, content)));
    }

    // A miss reads under its own lock, deciding the zone and the grant there
    // again; concurrent misses may load twice, each one complete serial.
    let loaded = fetch_transfer_content(cx, zone_name, key).await?;
    if let TransferAccess::Granted((zone, content)) = &loaded {
        dns_cx.transfer_cache.store_content(
            cx.metrics(),
            max_records,
            zone.id,
            zone.serial,
            content.clone(),
        );
    }
    Ok(loaded)
}

/// Pull both record planes of the zone by name, as far as `key` may read
/// them, straight from the service.
async fn fetch_transfer_content(
    dns_cx: &Context,
    zone_name: &ZoneName,
    key: Option<&TsigKey>,
) -> Result<TransferAccess<(Zone, CachedTransferContent)>, ServiceError> {
    Ok(
        zone::authorize_transfer_content_by_name(dns_cx, zone_name, key)
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

impl Entries {
    /// Advance the logical clock used to track cache recency.
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

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
    fn find(&mut self, zone_id: ZoneId, serial: Serial) -> Option<CachedTransferContent> {
        let now = self.tick();
        let entry = self
            .zones
            .get_mut(&zone_id)
            .filter(|entry| entry.serial == serial)?;
        entry.last_used = now;
        Some(entry.content.clone())
    }

    /// Store a zone within the record budget and return the number of evictions.
    fn store(
        &mut self,
        zone_id: ZoneId,
        serial: Serial,
        content: CachedTransferContent,
        max_records: usize,
    ) -> usize {
        // Before the size check: a zone that grew past the budget must release
        // its old serial, which no read can match any more.
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
        let last_used = self.tick();
        self.zones.insert(
            zone_id,
            CachedTransfer {
                serial,
                content,
                records,
                last_used,
            },
        );

        evicted
    }

    /// Remove a cached zone and subtract its records from the retained count.
    fn remove(&mut self, zone_id: ZoneId) {
        if let Some(removed) = self.zones.remove(&zone_id) {
            self.records -= removed.records;
        }
    }
}

#[cfg(test)]
mod tests;
