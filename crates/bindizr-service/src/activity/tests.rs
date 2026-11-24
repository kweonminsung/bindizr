use bindizr_db::ActivityLogSortField;
use chrono::TimeZone;

use super::*;
use crate::error::ErrorCode;

/// Verify that `normalize_filter` parses the entity, lowercases the name, and bounds the page.
#[test]
fn normalize_filter_parses_entity_and_folds_name_case() {
    let filter = normalize_filter(&ActivityLogFilter {
        entity: Some(" TSIG_KEY ".to_string()),
        name: Some(" Update-Key ".to_string()),
        limit: Some(10),
        offset: Some(5),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(filter.entity, Some("tsig_key".to_string()));
    assert_eq!(filter.name.as_deref(), Some("update-key"));
    assert_eq!(filter.limit, Some(10));
    assert_eq!(filter.offset, Some(5));
    assert_eq!(filter.sort, ActivityLogSortField::CreatedAt);
    assert_eq!(filter.order, SortOrder::Desc);
}

/// Verify that the name is spelled as its entity stores it, so a zone or a
/// TSIG key given with a trailing dot still finds its rows.
#[test]
fn normalize_filter_spells_the_name_as_its_entity_stores_it() {
    for (entity, name, expected) in [
        ("zone", "Example.COM.", "example.com"),
        ("tsig_key", "Update-Key.Example.", "update-key.example"),
        ("role", " Ops ", "ops"),
    ] {
        let filter = normalize_filter(&ActivityLogFilter {
            entity: Some(entity.to_string()),
            name: Some(name.to_string()),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(filter.name.as_deref(), Some(expected), "{entity}");
    }
}

/// Verify that `normalize_filter` reads the sort field and direction, and refuses unknown ones.
#[test]
fn normalize_filter_reads_sort_and_order() {
    let filter = normalize_filter(&ActivityLogFilter {
        sort: Some("target".to_string()),
        order: Some("asc".to_string()),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(filter.sort, ActivityLogSortField::Target);
    assert_eq!(filter.order, SortOrder::Asc);

    for (sort, order) in [(Some("name"), None), (None, Some("newest"))] {
        let error = normalize_filter(&ActivityLogFilter {
            sort: sort.map(str::to_string),
            order: order.map(str::to_string),
            ..Default::default()
        })
        .unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }
}

/// Verify that blank selectors normalize to absent without supplying a page limit.
#[test]
fn normalize_filter_reads_blank_selectors_as_absent() {
    let filter = normalize_filter(&ActivityLogFilter {
        entity: Some(String::new()),
        name: Some("   ".to_string()),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(filter.entity, None);
    assert_eq!(filter.name, None);
    assert_eq!(filter.limit, None);
}

/// Verify that `normalize_filter` rejects an unknown entity and an empty time window.
#[test]
fn normalize_filter_rejects_unknown_entity_and_inverted_window() {
    let unknown = normalize_filter(&ActivityLogFilter {
        entity: Some("unknown".to_string()),
        ..Default::default()
    })
    .unwrap_err();

    assert_eq!(unknown.code(), ErrorCode::InvalidInput);
    assert!(unknown.to_string().contains("unknown"), "{unknown}");

    let later = Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap();
    let inverted = normalize_filter(&ActivityLogFilter {
        since: Some(later),
        until: Some(later),
        ..Default::default()
    })
    .unwrap_err();

    assert_eq!(inverted.code(), ErrorCode::InvalidInput);
}
