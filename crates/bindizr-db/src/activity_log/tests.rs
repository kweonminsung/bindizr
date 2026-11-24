use bindizr_core::config::{DatabaseConfig, SqliteConfig};
use bindizr_core::model::activity_log::{ActivityOperation, ActivityResult, ActivityTarget};
use bindizr_core::model::change::{ChangeActor, ChangeSource};
use chrono::TimeDelta;

use super::*;

/// Open an isolated WAL database to let readers query during a write.
async fn database(directory: &tempfile::TempDir) -> Db {
    Db::connect(&DatabaseConfig {
        sqlite: SqliteConfig {
            file_path: directory
                .path()
                .join("activity.sqlite")
                .display()
                .to_string(),
        },
        ..DatabaseConfig::default()
    })
    .await
    .unwrap()
}

fn record_log(record_id: i32) -> ActivityLog {
    ActivityLog {
        id: 0,
        operation: ActivityOperation::RecordUpdate,
        result: ActivityResult::Changed,
        target: ActivityTarget {
            name: None,
            zone_name: Some("example.test".to_string()),
            record_id: Some(record_id),
            record_name: Some("www".to_string()),
            record_type: Some("A".to_string()),
        },
        source: ChangeSource::Nsupdate,
        actor: Some(ChangeActor::TsigKey {
            name: "updates".to_string(),
        }),
        created_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        detail: Some("test detail".to_string()),
    }
}

/// Keep uncommitted events out of listings and preserve the order of a batch
/// spanning multiple insert statements, even when its timestamps are tied.
#[tokio::test]
async fn activity_log_list_committed_batches_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let db = database(&directory).await;
    let filter = ActivityLogFilter {
        order: SortOrder::Asc,
        ..ActivityLogFilter::default()
    };
    let mut tx = db.begin().await.unwrap();
    create_tx(&mut tx, &record_log(10)).await.unwrap();

    assert!(list_by_filter(&db, &filter).await.unwrap().is_empty());
    tx.rollback().await.unwrap();
    assert!(list_by_filter(&db, &filter).await.unwrap().is_empty());

    let events = (1..=501).map(record_log).collect::<Vec<_>>();
    let mut tx = db.begin().await.unwrap();
    create_many_tx(&mut tx, &events).await.unwrap();
    tx.commit().await.unwrap();

    assert_eq!(count_by_filter(&db, &filter).await.unwrap(), 501);
    let first_page = ActivityLogFilter {
        limit: Some(1),
        ..filter.clone()
    };
    let first = list_by_filter(&db, &first_page).await.unwrap().remove(0);
    assert!(first.id > 0);
    assert_eq!(
        first,
        ActivityLog {
            id: first.id,
            ..record_log(1)
        }
    );

    let last_page = ActivityLogFilter {
        offset: Some(499),
        ..filter
    };
    let last = list_by_filter(&db, &last_page).await.unwrap();
    assert_eq!(last.len(), 2);
    assert_eq!(last[0].target.record_id, Some(500));
    assert_eq!(last[1].target.record_id, Some(501));
    assert!(first.id < last[0].id && last[0].id < last[1].id);
}

/// Reopening and pruning the log preserve unique ids for later activity.
#[tokio::test]
async fn activity_log_keep_ids_across_restart_and_pruning() {
    let directory = tempfile::tempdir().unwrap();
    let db = database(&directory).await;
    let filter = ActivityLogFilter::default();
    let event = record_log(1);
    let mut tx = db.begin().await.unwrap();
    create_tx(&mut tx, &event).await.unwrap();
    tx.commit().await.unwrap();
    let first = list_by_filter(&db, &filter).await.unwrap().remove(0);
    assert_eq!(
        prune_older_than(&db, event.created_at + TimeDelta::seconds(1))
            .await
            .unwrap(),
        1,
    );
    drop(db);

    let db = database(&directory).await;
    let mut tx = db.begin().await.unwrap();
    create_tx(&mut tx, &record_log(2)).await.unwrap();
    tx.commit().await.unwrap();

    let mut remaining = list_by_filter(&db, &filter).await.unwrap();
    assert_eq!(remaining.len(), 1);
    let second = remaining.remove(0);
    assert!(second.id > first.id);
    assert_eq!(
        second,
        ActivityLog {
            id: second.id,
            ..record_log(2)
        }
    );
}

/// A filtered page and its total use the same predicates and a stable sort.
#[tokio::test]
async fn activity_log_filter_targets_results_and_dates() {
    let directory = tempfile::tempdir().unwrap();
    let db = database(&directory).await;
    let first = record_log(1);
    let mut last = record_log(2);
    last.created_at += TimeDelta::days(1);
    let unchanged = ActivityLog {
        result: ActivityResult::Succeeded,
        ..record_log(3)
    };
    let named = ActivityLog {
        operation: ActivityOperation::RoleGrantCreate,
        target: ActivityTarget {
            name: Some("example.test".to_string()),
            ..ActivityTarget::default()
        },
        ..record_log(4)
    };

    let mut tx = db.begin().await.unwrap();
    create_many_tx(&mut tx, &[first.clone(), last.clone(), unchanged, named])
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut filter = ActivityLogFilter {
        entity: Some("record".to_string()),
        operation: Some(ActivityOperation::RecordUpdate),
        result: Some(ActivityResult::Changed),
        name: Some("example.test".to_string()),
        zone_name: Some("example.test".to_string()),
        record_name: Some("www".to_string()),
        record_type: Some("A".to_string()),
        since: Some(first.created_at),
        until: Some(last.created_at + TimeDelta::seconds(1)),
        sort: ActivityLogSortField::CreatedAt,
        order: SortOrder::Desc,
        limit: Some(1),
        offset: Some(1),
    };
    assert_eq!(count_by_filter(&db, &filter).await.unwrap(), 2);
    assert_eq!(
        list_by_filter(&db, &filter).await.unwrap(),
        [ActivityLog { id: 1, ..first }],
    );

    filter.until = Some(last.created_at);
    assert_eq!(count_by_filter(&db, &filter).await.unwrap(), 1);
    assert!(list_by_filter(&db, &filter).await.unwrap().is_empty());

    let named_filter = ActivityLogFilter {
        entity: Some("role_grant".to_string()),
        name: Some("example.test".to_string()),
        ..ActivityLogFilter::default()
    };
    let matching = list_by_filter(&db, &named_filter).await.unwrap();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].id, 4);
    assert_eq!(count_by_filter(&db, &named_filter).await.unwrap(), 1);
}
