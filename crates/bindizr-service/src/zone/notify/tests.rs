use std::time::Duration;

use bindizr_core::config::Config;
use bindizr_core::dns::CatalogZone;
use bindizr_core::dns::message::{Keepalive, Opcode, OptRcode, ParsedQuery};
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time;

use super::*;
use crate::error::ErrorCode;
use crate::types::{CreateSecondaryRequest, CreateZoneRequest, Run, UpdateZoneRequest};
use crate::{secondary, transaction, zone};

/// Set up an isolated database and a short timeout for loopback NOTIFY tests.
async fn context() -> Arc<Context> {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    config.dns.notify.timeout_secs = 1;
    config.dns.notify.retries = 0;
    let db = Db::connect(&config.database).await.unwrap();
    Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        mpsc::channel(1).0,
        watch::channel(0).0,
    ))
}

/// Create a zone with its apex nameserver.
async fn create_zone(cx: &Context, caller: &Caller, name: &str) -> ZoneName {
    let request = CreateZoneRequest {
        name: name.to_string(),
        mname: format!("ns.{name}"),
        rname: format!("hostmaster@{name}"),
        default_ttl: None,
        serial: None,
        refresh: None,
        retry: None,
        expire: None,
        minimum_ttl: None,
        description: None,
        apex_ns: true,
        dry_run: false,
    };
    zone::create(cx, caller, &request).await.unwrap();
    ZoneName::parse(name).unwrap()
}

/// Refresh the catalog from the enabled zones in its own transaction.
async fn refresh_catalog(cx: &Context) -> CatalogZone {
    let mut tx = transaction::begin_tx(cx, "failed to refresh the catalog")
        .await
        .unwrap();

    let refreshed = zone::refresh_catalog_tx(&mut tx, cx).await;

    transaction::finish_tx(tx, refreshed, "failed to refresh the catalog")
        .await
        .unwrap()
        .0
}

/// Verify that messages describe completed increments, including requests whose target has
/// none.
#[tokio::test]
async fn notify_reports_only_serials_it_advanced() {
    let cx = context().await;
    let caller = Caller::socket();

    let empty = notify(&cx, &caller, NotifyTarget::All, NotifySerial::Bump)
        .await
        .unwrap();
    assert_eq!(
        empty.message,
        "NOTIFY sent successfully for all enabled zones"
    );

    let catalog_zone = refresh_catalog(&cx).await;
    assert_eq!(u32::from(catalog_zone.serial), 1);
    let response = notify(
        &cx,
        &caller,
        NotifyTarget::Zone(&catalog_zone.name),
        NotifySerial::Bump,
    )
    .await
    .unwrap();
    assert_eq!(
        response.message,
        format!("NOTIFY sent successfully for zone: {}", catalog_zone.name)
    );
    assert_eq!(refresh_catalog(&cx).await.serial, catalog_zone.serial);

    let zone_name = create_zone(&cx, &caller, "example.test").await;
    let original = zone::get_by_name(&cx, &caller, &zone_name).await.unwrap();

    let kept = notify(
        &cx,
        &caller,
        NotifyTarget::Zone(&zone_name),
        NotifySerial::Keep,
    )
    .await
    .unwrap();
    assert!(!kept.message.contains("serial bumped"));
    assert_eq!(
        zone::get_by_name(&cx, &caller, &zone_name)
            .await
            .unwrap()
            .serial,
        original.serial
    );

    for target in [NotifyTarget::Zone(&zone_name), NotifyTarget::All] {
        let before = zone::get_by_name(&cx, &caller, &zone_name)
            .await
            .unwrap()
            .serial;
        let response = notify(&cx, &caller, target, NotifySerial::Bump)
            .await
            .unwrap();
        assert!(response.message.ends_with(" (serial bumped)"));
        assert!(
            zone::get_by_name(&cx, &caller, &zone_name)
                .await
                .unwrap()
                .serial
                .is_newer_than(before)
        );
    }

    // A zone selected by an all-zone round can be disabled before the
    // bump takes its lock. Neither its serial nor the round message advances.
    let selected = zone::list_enabled(&cx).await.unwrap().pop().unwrap();
    zone::update(
        &cx,
        &caller,
        &selected.name,
        &UpdateZoneRequest {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let disabled = zone::get_by_name(&cx, &caller, &selected.name)
        .await
        .unwrap();
    assert!(
        !bump_zone_serial(&cx, &caller, &selected.name)
            .await
            .unwrap()
    );
    let after = zone::get_by_name(&cx, &caller, &selected.name)
        .await
        .unwrap();
    assert_eq!(after.serial, disabled.serial);
    let all = notify(&cx, &caller, NotifyTarget::All, NotifySerial::Bump)
        .await
        .unwrap();
    assert_eq!(
        all.message,
        "NOTIFY sent successfully for all enabled zones"
    );
    let error = notify(
        &cx,
        &caller,
        NotifyTarget::Zone(&selected.name),
        NotifySerial::Bump,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("is disabled"));
}

/// Verify that a later missing zone preserves its error and still announces a committed bump.
#[tokio::test]
async fn announce_committed_bump_before_returning_later_failure() {
    let cx = context().await;
    let caller = Caller::socket();
    let first = create_zone(&cx, &caller, "a.example.test").await;
    let removed = create_zone(&cx, &caller, "b.example.test").await;
    let selected = zone::list_enabled(&cx).await.unwrap();
    let before = zone::get_by_name(&cx, &caller, &first)
        .await
        .unwrap()
        .serial;
    zone::delete(&cx, &caller, &removed, Run::Apply)
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    secondary::create(
        &cx,
        &caller,
        &CreateSecondaryRequest {
            name: "loopback".to_string(),
            address: socket.local_addr().unwrap().to_string(),
            notify_tsig_key_name: None,
        },
    )
    .await
    .unwrap();

    let receive = async {
        let mut data = [0; 4096];
        let (len, peer) = socket.recv_from(&mut data).await.unwrap();
        let query = ParsedQuery::parse(&data[..len], Keepalive::None).unwrap();
        assert_eq!(query.opcode, Opcode::NOTIFY);
        assert_eq!(query.zone_name, first.as_str());
        let after = zone::get_by_name(&cx, &caller, &first)
            .await
            .unwrap()
            .serial;
        assert!(after.is_newer_than(before));
        let response = query
            .build_signed_error_response(OptRcode::NOERROR, None, None)
            .unwrap();
        socket.send_to(&response, peer).await.unwrap();
    };
    let (_, result) = time::timeout(Duration::from_secs(4), async {
        tokio::join!(
            receive,
            bump_zone_serials(&cx, &caller, selected.into_iter().map(|zone| zone.name)),
        )
    })
    .await
    .unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code(), ErrorCode::ZoneNotFound);
    assert!(error.to_string().contains(removed.as_str()));
}
