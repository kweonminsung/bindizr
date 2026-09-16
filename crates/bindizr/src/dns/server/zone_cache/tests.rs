//! Cache eviction and the record accounting it evicts on.

use bindizr_core::{
    dns::name::OwnerName,
    model::record::{Record, RecordType},
};
use chrono::Utc;

use super::{Cache, CachedTransferContent};

const MAX_RECORDS: usize = 500_000;

/// Build cached zone content with the requested record count.
fn zone_content(records: usize) -> CachedTransferContent {
    let records = (0..records)
        .map(|i| Record {
            id: i as i32,
            name: OwnerName::from_row("www"),
            record_type: RecordType::A,
            value: "192.0.2.1".to_string(),
            ttl: 3600,
            priority: None,
            created_at: Utc::now(),
            zone_id: 1,
        })
        .collect();
    CachedTransferContent {
        records: std::sync::Arc::new(records),
        dnssec_records: std::sync::Arc::new(Vec::new()),
    }
}

/// Verify that a zone larger than the budget is served uncached.
#[test]
fn a_zone_larger_than_the_budget_is_served_uncached() {
    let mut cache = Cache::default();
    cache.store(1, 1, zone_content(MAX_RECORDS + 1), MAX_RECORDS);

    assert!(cache.lookup(1, 1).is_none());
    assert_eq!(cache.records, 0);
}

/// Verify that a zone that grows past the budget releases its old entry.
#[test]
fn a_zone_that_grows_past_the_budget_releases_its_old_entry() {
    let mut cache = Cache::default();
    cache.store(1, 1, zone_content(MAX_RECORDS / 2), MAX_RECORDS);
    cache.store(1, 2, zone_content(MAX_RECORDS + 1), MAX_RECORDS);

    assert!(cache.lookup(1, 1).is_none());
    assert!(cache.lookup(1, 2).is_none());
    assert_eq!(cache.records, 0);
}

/// Verify that a second large zone evicts the first to fit.
#[test]
fn a_second_large_zone_evicts_the_first_to_fit() {
    let mut cache = Cache::default();
    // A cap on zones would have held both, at 120% of the budget.
    cache.store(1, 1, zone_content(MAX_RECORDS * 3 / 5), MAX_RECORDS);
    cache.store(2, 1, zone_content(MAX_RECORDS * 3 / 5), MAX_RECORDS);

    assert!(cache.lookup(1, 1).is_none());
    assert!(cache.lookup(2, 1).is_some());
    assert!(cache.records <= MAX_RECORDS);
}

/// Verify that eviction drops the least recently used zone.
#[test]
fn eviction_drops_the_least_recently_used_zone() {
    let mut cache = Cache::default();
    cache.store(1, 1, zone_content(MAX_RECORDS * 2 / 5), MAX_RECORDS);
    cache.store(2, 1, zone_content(MAX_RECORDS * 2 / 5), MAX_RECORDS);
    assert!(cache.lookup(1, 1).is_some());

    // Fits only after one of the two is evicted, and zone 1 was just read.
    cache.store(3, 1, zone_content(MAX_RECORDS / 2), MAX_RECORDS);

    assert!(cache.lookup(2, 1).is_none());
    assert!(cache.lookup(1, 1).is_some());
    assert!(cache.lookup(3, 1).is_some());
}

/// Verify that restoring a zone replaces its records rather than adding them.
#[test]
fn restoring_a_zone_replaces_its_records_rather_than_adding_them() {
    let mut cache = Cache::default();
    let content = zone_content(4);
    let records = content.record_count();

    cache.store(1, 1, content.clone(), MAX_RECORDS);
    cache.store(1, 2, content, MAX_RECORDS);

    assert_eq!(cache.records, records);
    assert!(cache.lookup(1, 1).is_none());
    assert!(cache.lookup(1, 2).is_some());
}

/// Verify that a lowered budget reaches zones already cached.
#[test]
fn a_lowered_budget_reaches_zones_already_cached() {
    let mut cache = Cache::default();
    cache.store(1, 1, zone_content(3), 10);
    cache.store(2, 1, zone_content(3), 10);
    assert_eq!(cache.records, 6);

    assert_eq!(cache.trim_to(3), 1);
    assert_eq!(cache.records, 3);
    assert!(cache.lookup(1, 1).is_none(), "the older zone went first");
    assert!(cache.lookup(2, 1).is_some());
}
