use bindizr_core::config::Config;
use bindizr_core::dns::CatalogZone;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::types::CreateZoneRequest;
use crate::{transaction, zone};

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
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    let db = Db::connect(&config.database).await.unwrap();
    let cx = Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        mpsc::channel(1).0,
        watch::channel(0).0,
    ));
    let caller = Caller::socket();

    let empty = notify(&cx, &caller, NotifyTarget::All, NotifySerial::Bump)
        .await
        .unwrap();
    assert_eq!(empty.message, "NOTIFY sent successfully for all zones");

    let catalog_zone = refresh_catalog(&cx).await;
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

    let request = CreateZoneRequest {
        name: "example.test".to_string(),
        mname: "ns.example.test".to_string(),
        rname: "hostmaster@example.test".to_string(),
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
    zone::create(&cx, &caller, &request).await.unwrap();
    let zone_name = ZoneName::parse("example.test").unwrap();
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
}
