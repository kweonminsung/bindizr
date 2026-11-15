use std::sync::Arc;

use bindizr_core::config::Config;
use bindizr_core::metrics::Metrics;
use bindizr_core::model::change::ChangeActor;
use bindizr_db::Db;
use chrono::{DateTime, Duration, TimeZone, Utc};
use tokio::sync::{mpsc, watch};

use super::*;
use crate::error::ErrorCode;

/// Build service state over a disposable database whose access log queue
/// holds `capacity` rows, returning the queue's receiving end.
async fn context(save: SavedRequests, capacity: usize) -> (Arc<Context>, Receiver<AccessLog>) {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    config.access_log.save = save;

    let db = Db::connect(&config.database).await.unwrap();
    let (access_tx, access_rx) = mpsc::channel(capacity);
    let cx = Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        access_tx,
        watch::channel(0).0,
    );

    (Arc::new(cx), access_rx)
}

/// Build an API request row answered with `status` at `requested_at`.
fn test_log(
    result: AccessResult,
    status: &str,
    caller: Option<&str>,
    requested_at: DateTime<Utc>,
) -> AccessLog {
    AccessLog {
        source: AccessSource::Api,
        client_addr: "192.0.2.1".to_string(),
        method: "GET".to_string(),
        target: "/zones".to_string(),
        status: status.to_string(),
        result,
        caller: caller.map(|name| ChangeActor::Token {
            name: name.to_string(),
        }),
        error: None,
        requested_at,
    }
}

/// Save `logs` through the writer and wait until it has written them all.
async fn save_all(cx: &Arc<Context>, access_rx: Receiver<AccessLog>, logs: Vec<AccessLog>) {
    let worker = spawn(cx.clone(), access_rx);

    for log in logs {
        save(cx, log);
    }

    worker.stop().await.unwrap();
}

/// List every row `filter` selects as its status, newest first.
async fn list_statuses(cx: &Context, filter: AccessLogFilter) -> Vec<String> {
    list(cx, &Caller::socket(), &filter)
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|log| log.status)
        .collect()
}

/// Verify that the writer saves every queued row before it stops, newest listed first.
#[tokio::test]
async fn save_writes_every_queued_row_before_the_worker_stops() {
    let (cx, access_rx) = context(SavedRequests::All, 16).await;
    let now = Utc::now();

    save_all(
        &cx,
        access_rx,
        vec![
            test_log(AccessResult::Ok, "200", Some("deploy"), now),
            test_log(AccessResult::Denied, "401", None, now),
            test_log(AccessResult::Failed, "404", Some("deploy"), now),
        ],
    )
    .await;

    assert_eq!(
        list_statuses(&cx, AccessLogFilter::default()).await,
        ["404", "401", "200"]
    );
}

/// Verify that `access_log.save = "denied"` saves denials alone.
#[tokio::test]
async fn save_keeps_only_denials_when_only_denied_requests_are_saved() {
    let (cx, access_rx) = context(SavedRequests::Denied, 16).await;
    let now = Utc::now();

    save_all(
        &cx,
        access_rx,
        vec![
            test_log(AccessResult::Ok, "200", None, now),
            test_log(AccessResult::Denied, "403", None, now),
            test_log(AccessResult::Failed, "500", None, now),
        ],
    )
    .await;

    assert_eq!(
        list_statuses(&cx, AccessLogFilter::default()).await,
        ["403"]
    );
}

/// Verify that a full queue drops the row and counts the drop instead of waiting.
#[tokio::test]
async fn save_drops_and_counts_a_row_the_full_queue_cannot_take() {
    let (cx, _access_rx) = context(SavedRequests::All, 1).await;
    let now = Utc::now();

    save(&cx, test_log(AccessResult::Ok, "200", None, now));
    save(&cx, test_log(AccessResult::Ok, "200", None, now));

    assert!(
        cx.metrics()
            .encode()
            .contains("bindizr_access_log_dropped_total 1"),
        "the second row found the queue full"
    );
}

/// Verify that a listing applies its result, caller, address, time window and page.
#[tokio::test]
async fn list_applies_result_caller_address_window_and_page() {
    let (cx, access_rx) = context(SavedRequests::All, 16).await;
    let now = Utc::now();
    let mut from_other = test_log(AccessResult::Ok, "201", Some("deploy"), now);
    from_other.client_addr = "2001:db8::1".to_string();

    save_all(
        &cx,
        access_rx,
        vec![
            test_log(
                AccessResult::Ok,
                "200",
                Some("deploy"),
                now - Duration::days(3),
            ),
            test_log(
                AccessResult::Denied,
                "403",
                Some("ci"),
                now - Duration::days(2),
            ),
            from_other,
        ],
    )
    .await;

    for (filter, expected) in [
        (
            AccessLogFilter {
                result: Some("DENIED".to_string()),
                ..Default::default()
            },
            vec!["403"],
        ),
        (
            AccessLogFilter {
                caller_name: Some(" Deploy ".to_string()),
                ..Default::default()
            },
            vec!["201", "200"],
        ),
        (
            AccessLogFilter {
                address: Some("2001:0db8::0001".to_string()),
                ..Default::default()
            },
            vec!["201"],
        ),
        (
            AccessLogFilter {
                since: Some(now - Duration::days(4)),
                until: Some(now - Duration::days(1)),
                ..Default::default()
            },
            vec!["403", "200"],
        ),
        (
            AccessLogFilter {
                limit: Some(1),
                offset: Some(1),
                ..Default::default()
            },
            vec!["403"],
        ),
    ] {
        assert_eq!(
            list_statuses(&cx, filter.clone()).await,
            expected,
            "{filter:?}"
        );
    }
}

/// Verify that `normalize_filter` rejects unknown values, a non-IP address and an empty window.
#[test]
fn normalize_filter_rejects_unknown_values_and_inverted_window() {
    let later = Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap();

    for filter in [
        AccessLogFilter {
            source: Some("socket".to_string()),
            ..Default::default()
        },
        AccessLogFilter {
            result: Some("refused".to_string()),
            ..Default::default()
        },
        AccessLogFilter {
            address: Some("ns2.example.net".to_string()),
            ..Default::default()
        },
        AccessLogFilter {
            since: Some(later),
            until: Some(later),
            ..Default::default()
        },
    ] {
        let error = normalize_filter(&filter).unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidInput, "{filter:?}");
    }
}
