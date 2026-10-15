//! Entries eviction and the record accounting it evicts on.

use bindizr_core::{
    dns::{Ttl, name::OwnerName},
    model::{
        record::{Record, RecordId, RecordType},
        zone::ZoneId,
        zone_version::ZoneVersionId,
    },
};
use chrono::Utc;

use super::*;

const MAX_RECORDS: usize = 500_000;

/// Build cached zone content with the requested record count.
fn zone_content(records: usize) -> CachedTransferContent {
    let records = (0..records)
        .map(|i| Record {
            id: RecordId::from(i as i32),
            name: OwnerName::from_row("www"),
            record_type: RecordType::A,
            value: "192.0.2.1".to_string(),
            ttl: Ttl::try_from(3600).unwrap(),
            priority: None,
            created_at: Utc::now(),
            zone_id: ZoneId::from(1),
        })
        .collect();
    CachedTransferContent {
        version_id: ZoneVersionId::from(1),
        records: std::sync::Arc::new(records),
        dnssec_records: std::sync::Arc::new(Vec::new()),
    }
}

/// Verify that a zone larger than the budget is served uncached.
#[test]
fn transfer_cache_serves_oversized_zone_without_caching() {
    let mut entries = Entries::default();
    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS + 1),
        MAX_RECORDS,
    );

    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_none()
    );
    assert_eq!(entries.records, 0);
}

/// Verify that a zone that grows past the budget releases its old entry.
#[test]
fn transfer_cache_releases_entry_when_zone_exceeds_budget() {
    let mut entries = Entries::default();
    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS / 2),
        MAX_RECORDS,
    );
    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(2),
        zone_content(MAX_RECORDS + 1),
        MAX_RECORDS,
    );

    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_none()
    );
    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(2))
            .is_none()
    );
    assert_eq!(entries.records, 0);
}

/// Verify that a second large zone evicts the first to fit.
#[test]
fn transfer_cache_evicts_previous_zone_to_fit_new_zone() {
    let mut entries = Entries::default();
    // A cap on zones would have held both, at 120% of the budget.
    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS * 3 / 5),
        MAX_RECORDS,
    );
    entries.store(
        ZoneId::from(2),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS * 3 / 5),
        MAX_RECORDS,
    );

    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_none()
    );
    assert!(
        entries
            .find(ZoneId::from(2), ZoneVersionId::from(1))
            .is_some()
    );
    assert!(entries.records <= MAX_RECORDS);
}

/// Verify that eviction drops the least recently used zone.
#[test]
fn transfer_cache_evicts_least_recently_used_zone() {
    let mut entries = Entries::default();
    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS * 2 / 5),
        MAX_RECORDS,
    );
    entries.store(
        ZoneId::from(2),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS * 2 / 5),
        MAX_RECORDS,
    );
    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_some()
    );

    // Fits only after one of the two is evicted, and zone 1 was just read.
    entries.store(
        ZoneId::from(3),
        ZoneVersionId::from(1),
        zone_content(MAX_RECORDS / 2),
        MAX_RECORDS,
    );

    assert!(
        entries
            .find(ZoneId::from(2), ZoneVersionId::from(1))
            .is_none()
    );
    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_some()
    );
    assert!(
        entries
            .find(ZoneId::from(3), ZoneVersionId::from(1))
            .is_some()
    );
}

/// Verify that restoring a zone replaces its records rather than adding them.
#[test]
fn transfer_cache_replaces_records_when_zone_is_restored() {
    let mut entries = Entries::default();
    let content = zone_content(4);
    let records = content.record_count();

    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(1),
        content.clone(),
        MAX_RECORDS,
    );
    entries.store(
        ZoneId::from(1),
        ZoneVersionId::from(2),
        content,
        MAX_RECORDS,
    );

    assert_eq!(entries.records, records);
    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_none()
    );
    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(2))
            .is_some()
    );
}

/// Verify that a lowered budget reaches zones already cached.
#[test]
fn transfer_cache_evicts_existing_zones_when_budget_is_lowered() {
    let mut entries = Entries::default();
    entries.store(ZoneId::from(1), ZoneVersionId::from(1), zone_content(3), 10);
    entries.store(ZoneId::from(2), ZoneVersionId::from(1), zone_content(3), 10);
    assert_eq!(entries.records, 6);

    assert_eq!(entries.trim_to(3), 1);
    assert_eq!(entries.records, 3);
    assert!(
        entries
            .find(ZoneId::from(1), ZoneVersionId::from(1))
            .is_none(),
        "the older zone went first"
    );
    assert!(
        entries
            .find(ZoneId::from(2), ZoneVersionId::from(1))
            .is_some()
    );
}
