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
async fn context(save: SavedRequests, capacity: usize) -> (Arc<Context>, Receiver<AccessLogEntry>) {
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

/// Build an API request row answered with `response_code` at `requested_at`.
fn test_log(
    result: AccessResult,
    response_code: &str,
    actor: Option<&str>,
    requested_at: DateTime<Utc>,
) -> AccessLogEntry {
    AccessLogEntry {
        source: AccessSource::Api,
        client_ip: "192.0.2.1".to_string(),
        method: "GET".to_string(),
        target: "/zones".to_string(),
        response_code: response_code.to_string(),
        result,
        actor: actor.map(|name| ChangeActor::Token {
            name: name.to_string(),
        }),
        error_code: None,
        requested_at,
    }
}

/// Save `logs` through the writer and wait until it has written them all.
async fn save_all(
    cx: &Arc<Context>,
    access_rx: Receiver<AccessLogEntry>,
    logs: Vec<AccessLogEntry>,
) {
    let worker = spawn(cx.clone(), access_rx);

    for log in logs {
        save(cx, log);
    }

    worker.stop().await.unwrap();
}

/// List every row `filter` selects as its response_code, newest first.
async fn list_response_codes(cx: &Context, filter: AccessLogFilter) -> Vec<String> {
    list(cx, &Caller::socket(), &filter)
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|log| log.response_code)
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
        list_response_codes(&cx, AccessLogFilter::default()).await,
        ["404", "401", "200"]
    );
}

/// Verify that typed service, DNS, TSIG and encoding errors retain their codes through queueing and storage.
#[tokio::test]
async fn save_preserves_error_codes_through_the_queue() {
    let (cx, access_rx) = context(SavedRequests::All, 16).await;
    let now = Utc::now();
    let cases = [
        (
            AccessSource::Api,
            AccessLogErrorCode::Service(ErrorCode::InvalidRecordValue),
            "INVALID_RECORD_VALUE",
        ),
        (
            AccessSource::Nsupdate,
            AccessLogErrorCode::Dns(OptRcode::BADVERS),
            "BADVERS",
        ),
        (
            AccessSource::Nsupdate,
            AccessLogErrorCode::Tsig(TsigRcode::BADSIG),
            "BADSIG(16)",
        ),
        (
            AccessSource::Nsupdate,
            AccessLogErrorCode::TsigAuthenticationFailed,
            "TSIG_AUTHENTICATION_FAILED",
        ),
        (
            AccessSource::Nsupdate,
            AccessLogErrorCode::TsigResponseEncodingFailed,
            "TSIG_RESPONSE_ENCODING_FAILED",
        ),
        (
            AccessSource::Nsupdate,
            AccessLogErrorCode::ResponseEncodingFailed,
            "RESPONSE_ENCODING_FAILED",
        ),
    ];
    let logs = cases
        .iter()
        .map(|(source, code, _)| {
            let mut log = test_log(AccessResult::Failed, "failure", Some("deploy"), now);
            log.source = *source;
            log.error_code = Some(*code);
            log
        })
        .collect();

    save_all(&cx, access_rx, logs).await;

    let logs = list(&cx, &Caller::socket(), &AccessLogFilter::default())
        .await
        .unwrap();
    let codes: Vec<_> = logs
        .items
        .iter()
        .map(|log| (log.source, log.error_code.as_deref().unwrap()))
        .collect();
    let expected: Vec<_> = cases
        .iter()
        .rev()
        .map(|(source, _, text)| (*source, *text))
        .collect();

    assert_eq!(codes, expected);
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
        list_response_codes(&cx, AccessLogFilter::default()).await,
        ["403"]
    );
}

/// Verify that `access_log.save = "none"` saves no request, denials included.
#[tokio::test]
async fn save_keeps_nothing_when_no_requests_are_saved() {
    let (cx, access_rx) = context(SavedRequests::None, 16).await;
    let now = Utc::now();

    save_all(
        &cx,
        access_rx,
        vec![
            test_log(AccessResult::Ok, "200", None, now),
            test_log(AccessResult::Denied, "403", None, now),
        ],
    )
    .await;

    assert!(
        list_response_codes(&cx, AccessLogFilter::default())
            .await
            .is_empty()
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
            .unwrap()
            .contains("bindizr_access_log_dropped_total 1"),
        "the second row found the queue full"
    );
}

/// Verify that a listing applies its result, actor, address, time window, order and page.
#[tokio::test]
async fn list_applies_result_actor_ip_window_order_and_page() {
    let (cx, access_rx) = context(SavedRequests::All, 16).await;
    let now = Utc::now();
    let mut from_other = test_log(AccessResult::Ok, "201", Some("deploy"), now);
    from_other.client_ip = "2001:db8::1".to_string();

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
                actor_name: Some(" Deploy ".to_string()),
                ..Default::default()
            },
            vec!["201", "200"],
        ),
        (
            AccessLogFilter {
                client_ip: Some("2001:0db8::0001".to_string()),
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
        (
            AccessLogFilter {
                // Sort and order read like every other parameter: case and
                // surrounding space aside.
                sort: Some(" Response_Code ".to_string()),
                order: Some("ASC".to_string()),
                ..Default::default()
            },
            vec!["200", "201", "403"],
        ),
    ] {
        assert_eq!(
            list_response_codes(&cx, filter.clone()).await,
            expected,
            "{filter:?}"
        );
    }
}

/// Verify that selectors ignore case and surrounding space, mapped addresses match IPv4, and blanks stay absent.
#[test]
fn normalize_filter_preserves_selector_and_address_semantics() {
    let defaults = bindizr_db::access_log::AccessLogFilter::default();
    for (address, expected) in [
        (None, None),
        (Some(" \t "), None),
        (Some(" ::ffff:192.0.2.1 "), Some("192.0.2.1")),
        (Some(" 2001:0db8::0001 "), Some("2001:db8::1")),
    ] {
        let filter = normalize_filter(&AccessLogFilter {
            source: Some(" ApI ".to_string()),
            result: Some(" oK ".to_string()),
            client_ip: address.map(str::to_string),
            sort: Some(" ".to_string()),
            order: Some("\t".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(filter.source, Some(AccessSource::Api));
        assert_eq!(filter.result, Some(AccessResult::Ok));
        assert_eq!(filter.client_ip.as_deref(), expected, "{address:?}");
        assert_eq!(filter.sort, defaults.sort);
        assert_eq!(filter.order, defaults.order);
    }

    let filter = normalize_filter(&AccessLogFilter {
        source: Some(" ".to_string()),
        result: Some(String::new()),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(filter.source, None);
    assert_eq!(filter.result, None);
}

/// Verify that `normalize_filter` rejects unknown values and sorts, a non-IP address and an empty window.
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
            client_ip: Some(" ns2.example.net ".to_string()),
            ..Default::default()
        },
        AccessLogFilter {
            since: Some(later),
            until: Some(later),
            ..Default::default()
        },
        AccessLogFilter {
            sort: Some("method".to_string()),
            ..Default::default()
        },
    ] {
        let error = normalize_filter(&filter).unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidInput, "{filter:?}");
        if filter.client_ip.is_some() {
            assert_eq!(
                error.to_string(),
                "address 'ns2.example.net' is not an IP address"
            );
        }
    }
}
