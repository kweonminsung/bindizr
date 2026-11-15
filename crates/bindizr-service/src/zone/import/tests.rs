use std::io;
use std::net::TcpListener;

use bindizr_core::config::Config;
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use tokio::sync::{mpsc, watch};

use super::*;
use crate::dns_client::axfr::FetchZoneError;
use crate::error::ErrorCode;
use crate::types::{ImportZoneRequest, ImportZonesRequest};
use crate::zone;

/// Verify that a failed external import keeps its network cause without creating a zone.
#[tokio::test]
async fn failed_zone_and_catalog_transfers_preserve_their_sources() {
    use std::error::Error;

    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();

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
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let zone_name = ZoneName::parse("example.com").unwrap();
    let caller = Caller::socket();

    let single = import(
        &cx,
        &caller,
        &zone_name,
        &ImportZoneRequest {
            content: None,
            from_server: Some(address.clone()),
            mode: "append".to_string(),
            dry_run: false,
            create: true,
        },
    )
    .await
    .unwrap_err();
    let catalog = import_many(
        &cx,
        &caller,
        &ImportZonesRequest {
            from_server: address.clone(),
            zone_names: None,
            from_catalog: Some("catalog.example".to_string()),
            mode: "append".to_string(),
            dry_run: false,
            create: true,
        },
    )
    .await
    .unwrap_err();

    for (error, context) in [
        (single, format!("AXFR from {address} failed")),
        (
            catalog,
            format!("AXFR of catalog catalog.example from {address} failed"),
        ),
    ] {
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        let source = error.source().unwrap();

        assert!(source.downcast_ref::<FetchZoneError>().is_some());
        assert_eq!(error.to_string(), format!("{context}: {source}"));
        let cause = source.source().unwrap().source().unwrap();

        assert!(matches!(
            cause.downcast_ref::<io::Error>(),
            Some(cause) if cause.kind() == io::ErrorKind::ConnectionRefused
        ));
    }

    assert!(zone::list(&cx).await.unwrap().is_empty());
}

/// Verify that zone names normalize and deduplicate in request order.
#[test]
fn normalize_zone_names_canonicalizes_and_drops_repeats() {
    let names = ["Example.COM.", "example.net", " example.com", "example.net"].map(str::to_string);

    let zone_names = normalize_zone_names(&names).unwrap();

    assert_eq!(
        zone_names,
        [
            ZoneName::parse("example.com").unwrap(),
            ZoneName::parse("example.net").unwrap(),
        ]
    );
}

/// Verify that zone-name lists reject empty input and invalid names.
#[test]
fn normalize_zone_names_rejects_empty_list_and_bad_name() {
    let empty = normalize_zone_names(&[]).unwrap_err();
    assert_eq!(empty.code(), ErrorCode::InvalidInput);

    let root = normalize_zone_names(&["example.com".to_string(), ".".to_string()]).unwrap_err();
    assert_eq!(root.code(), ErrorCode::InvalidZoneField);
}
