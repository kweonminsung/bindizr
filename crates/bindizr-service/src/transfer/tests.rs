use std::net::Ipv4Addr;

use bindizr_core::config::Config;
use bindizr_core::metrics::Metrics;
use bindizr_db::{Db, transfer_log};
use chrono::{DateTime, Duration};
use tokio::sync::{mpsc, watch};

use super::*;
use crate::authorization::Caller;
use crate::error::ErrorCode;
use crate::types::CreateZoneRequest;
use crate::zone;

/// The client address every test transfer is served to.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// Build service state over a disposable database holding the named zones.
async fn context(save: SavedTransfers, zone_names: &[&str]) -> (Context, Vec<ZoneId>) {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    config.transfer_log.save = save;

    let db = Db::connect(&config.database).await.unwrap();
    let cx = Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        mpsc::channel(1).0,
        watch::channel(0).0,
    );
    let mut zone_ids = Vec::new();

    for zone_name in zone_names {
        let request = CreateZoneRequest {
            name: zone_name.to_string(),
            mname: format!("ns.{zone_name}"),
            rname: format!("hostmaster@{zone_name}"),
            default_ttl: None,
            serial: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum_ttl: None,
            description: None,
            apex_ns: false,
            dry_run: false,
        };
        let created = zone::create(&cx, &Caller::socket(), &request)
            .await
            .unwrap();

        zone_ids.push(created.zone.id.unwrap());
    }

    (cx, zone_ids)
}

/// Build a served AXFR of `zone_id` answered at `served_at`.
fn test_log(zone_id: ZoneId, served_at: DateTime<Utc>) -> TransferLog {
    TransferLog {
        client_addr: CLIENT.to_string(),
        zone_id,
        kind: TransferKind::Axfr,
        result: TransferResult::Ok,
        transport: TransferTransport::Tcp,
        incremental: false,
        serial: Some(Serial::from(1)),
        served_at,
        error: None,
    }
}

/// Save each of `days_ago` as a transfer of its zone, oldest first.
async fn save_at(cx: &Context, now: DateTime<Utc>, transfers: &[(ZoneId, i64)]) {
    for (zone_id, days_ago) in transfers {
        let log = test_log(*zone_id, now - Duration::days(*days_ago));

        bindizr_db::transfer_log::create(cx.db(), log)
            .await
            .unwrap();
    }
}

/// List every row `filter` selects, newest first.
async fn list_logs(
    cx: &Context,
    filter: &transfer_log::TransferLogFilter,
) -> Vec<TransferLogWithZone> {
    bindizr_db::transfer_log::list_by_filter_with_zone(cx.db(), filter)
        .await
        .unwrap()
}

/// List the zone and age in days of each transfer `filter` selects, newest first.
/// Ages round to the nearest day, since a backend may store whole seconds.
async fn list_ages(
    cx: &Context,
    now: DateTime<Utc>,
    filter: &transfer_log::TransferLogFilter,
) -> Vec<(String, i64)> {
    list_logs(cx, filter)
        .await
        .iter()
        .map(|log| {
            let age = now - log.served_at + Duration::hours(12);
            (log.zone_name.to_string(), age.num_days())
        })
        .collect()
}

/// Verify that every answer appends a row and the newest is the zone's latest transfer.
#[tokio::test]
async fn save_appends_a_row_per_transfer_and_latest_reads_the_newest() {
    let (cx, zone_ids) = context(SavedTransfers::All, &["example.test"]).await;
    let (axfr, tcp) = (TransferKind::Axfr, TransferTransport::Tcp);

    save_refused(
        &cx,
        CLIENT,
        "example.test",
        axfr,
        tcp,
        "refused".to_string(),
    )
    .await;
    save_ok(&cx, CLIENT, zone_ids[0], axfr, tcp, false, Serial::from(7)).await;
    save_failed(&cx, CLIENT, "example.test", axfr, tcp, "closed".to_string()).await;

    let logs = list_logs(&cx, &transfer_log::TransferLogFilter::default()).await;
    let results: Vec<_> = logs.iter().map(|log| log.result).collect();

    assert_eq!(
        results,
        [
            TransferResult::Failed,
            TransferResult::Ok,
            TransferResult::Refused
        ]
    );
    // The failure that followed did not erase the serial last served.
    assert_eq!(logs[1].serial, Some(Serial::from(7)));

    let latest = list_latest_by_clients(&cx, &[CLIENT]).await.unwrap();
    let zone_name = ZoneName::parse("example.test").unwrap();
    let found = find_by_clients_and_zone_name(&cx, &[CLIENT], &zone_name)
        .await
        .unwrap();

    assert_eq!(latest.len(), 1, "{latest:?}");
    assert_eq!(latest[0].result, TransferResult::Failed);
    assert_eq!(found.map(|log| log.result), Some(TransferResult::Failed));
}

/// Verify that `transfer_log.save = "unserved"` saves refusals and failures alone.
#[tokio::test]
async fn save_ok_leaves_no_row_when_only_unserved_transfers_are_saved() {
    let (cx, zone_ids) = context(SavedTransfers::Unserved, &["example.test"]).await;
    let (axfr, tcp) = (TransferKind::Axfr, TransferTransport::Tcp);

    save_ok(&cx, CLIENT, zone_ids[0], axfr, tcp, false, Serial::from(7)).await;
    save_refused(
        &cx,
        CLIENT,
        "example.test",
        axfr,
        tcp,
        "refused".to_string(),
    )
    .await;

    let logs = list_logs(&cx, &transfer_log::TransferLogFilter::default()).await;

    assert_eq!(logs.len(), 1, "{logs:?}");
    assert_eq!(logs[0].result, TransferResult::Refused);
}

/// Verify that `transfer_log.save = "none"` saves no transfer, served or not.
#[tokio::test]
async fn save_leaves_no_row_when_no_transfers_are_saved() {
    let (cx, zone_ids) = context(SavedTransfers::None, &["example.test"]).await;
    let (axfr, tcp) = (TransferKind::Axfr, TransferTransport::Tcp);

    save_ok(&cx, CLIENT, zone_ids[0], axfr, tcp, false, Serial::from(7)).await;
    save_refused(
        &cx,
        CLIENT,
        "example.test",
        axfr,
        tcp,
        "refused".to_string(),
    )
    .await;
    save_failed(
        &cx,
        CLIENT,
        "example.test",
        axfr,
        tcp,
        "broken pipe".to_string(),
    )
    .await;

    let logs = list_logs(&cx, &transfer_log::TransferLogFilter::default()).await;

    assert!(logs.is_empty(), "{logs:?}");
}

/// Verify that a listing applies its zone, its time window, and its page.
#[tokio::test]
async fn list_by_filter_with_zone_applies_zone_time_window_and_page() {
    let (cx, zone_ids) = context(SavedTransfers::All, &["a.test", "b.test"]).await;
    let now = Utc::now();
    let half_day = Duration::hours(12);

    save_at(
        &cx,
        now,
        &[(zone_ids[0], 3), (zone_ids[1], 2), (zone_ids[0], 1)],
    )
    .await;

    for (filter, expected) in [
        (
            transfer_log::TransferLogFilter::default(),
            vec![("a.test", 1), ("b.test", 2), ("a.test", 3)],
        ),
        (
            transfer_log::TransferLogFilter {
                zone_name: Some(ZoneName::parse("a.test").unwrap()),
                ..Default::default()
            },
            vec![("a.test", 1), ("a.test", 3)],
        ),
        (
            transfer_log::TransferLogFilter {
                since: Some(now - Duration::days(2) - half_day),
                until: Some(now - Duration::days(1) - half_day),
                ..Default::default()
            },
            vec![("b.test", 2)],
        ),
        (
            transfer_log::TransferLogFilter {
                limit: Some(2),
                ..Default::default()
            },
            vec![("a.test", 1), ("b.test", 2)],
        ),
        (
            transfer_log::TransferLogFilter {
                limit: Some(1),
                offset: Some(1),
                ..Default::default()
            },
            vec![("b.test", 2)],
        ),
        (
            transfer_log::TransferLogFilter {
                client_addrs: Some(vec!["192.0.2.99".to_string()]),
                ..Default::default()
            },
            Vec::new(),
        ),
        (
            transfer_log::TransferLogFilter {
                client_addrs: Some(Vec::new()),
                ..Default::default()
            },
            Vec::new(),
        ),
    ] {
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(zone_name, days)| (zone_name.to_string(), days))
            .collect();

        assert_eq!(
            list_ages(&cx, now, &filter.clone()).await,
            expected,
            "{filter:?}"
        );
    }
}

/// Verify that pruning spares recent rows and the newest row of each client and zone.
#[tokio::test]
async fn prune_older_than_keeps_the_newest_row_of_each_client_and_zone() {
    let (cx, zone_ids) = context(SavedTransfers::All, &["a.test", "b.test"]).await;
    let now = Utc::now();
    let (a_zone_id, b_zone_id) = (zone_ids[0], zone_ids[1]);

    // a.test has a recent transfer; b.test's newest is older than the cutoff.
    save_at(
        &cx,
        now,
        &[
            (a_zone_id, 40),
            (b_zone_id, 35),
            (a_zone_id, 30),
            (b_zone_id, 20),
            (a_zone_id, 1),
        ],
    )
    .await;

    let cutoff = now - Duration::days(10);
    let pruned = bindizr_db::transfer_log::prune_older_than(cx.db(), cutoff)
        .await
        .unwrap();

    assert_eq!(pruned, 3);
    assert_eq!(
        list_ages(&cx, now, &transfer_log::TransferLogFilter::default()).await,
        [("a.test".to_string(), 1), ("b.test".to_string(), 20)]
    );
}

/// Verify that `list` reads the address, result and order, and refuses what it cannot parse or find.
#[tokio::test]
async fn list_selects_by_address_and_result_orders_and_rejects_bad_filters() {
    let (cx, zone_ids) = context(SavedTransfers::All, &["example.test"]).await;
    let (axfr, tcp) = (TransferKind::Axfr, TransferTransport::Tcp);

    save_ok(&cx, CLIENT, zone_ids[0], axfr, tcp, false, Serial::from(7)).await;
    save_refused(
        &cx,
        CLIENT,
        "example.test",
        axfr,
        tcp,
        "refused".to_string(),
    )
    .await;

    let refused = list(
        &cx,
        &Caller::socket(),
        &TransferLogFilter {
            address: Some(CLIENT.to_string()),
            result: Some("Refused".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(refused.pagination.total, 1, "{refused:?}");
    assert_eq!(refused.items[0].result, TransferResult::Refused);

    let by_result = list(
        &cx,
        &Caller::socket(),
        &TransferLogFilter {
            sort: Some("result".to_string()),
            order: Some("asc".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let results: Vec<_> = by_result.items.iter().map(|log| log.result).collect();

    assert_eq!(results, [TransferResult::Ok, TransferResult::Refused]);

    for (filter, code) in [
        (
            TransferLogFilter {
                result: Some("served".to_string()),
                ..Default::default()
            },
            ErrorCode::InvalidInput,
        ),
        (
            TransferLogFilter {
                address: Some("ns2.example.net".to_string()),
                ..Default::default()
            },
            ErrorCode::InvalidInput,
        ),
        (
            TransferLogFilter {
                sort: Some("served_at".to_string()),
                ..Default::default()
            },
            ErrorCode::InvalidInput,
        ),
        (
            TransferLogFilter {
                secondary_name: Some("ns9".to_string()),
                ..Default::default()
            },
            ErrorCode::SecondaryNotFound,
        ),
    ] {
        let error = list(&cx, &Caller::socket(), &filter).await.unwrap_err();

        assert_eq!(error.code(), code, "{filter:?}");
    }
}
