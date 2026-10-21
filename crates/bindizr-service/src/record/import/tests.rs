use super::*;
use crate::{
    error::ErrorCode,
    types::{ImportZoneRequest, ImportZonesRequest},
};

/// A failed external import keeps its network cause without creating a zone.
#[tokio::test]
async fn failed_zone_and_catalog_transfers_preserve_their_sources() {
    use std::{error::Error, io, net::TcpListener};

    use bindizr_core::{config::Config, metrics::Metrics};

    use crate::dns_client::axfr::FetchZoneError;

    let config: Config = serde_json::from_value(serde_json::json!({
        "database": { "sqlite": { "file_path": "sqlite::memory:" } },
    }))
    .unwrap();
    let db = bindizr_db::Db::connect(&config.database).await.unwrap();
    let (notify_jobs, _jobs) = tokio::sync::mpsc::unbounded_channel();
    let (scheduler, _period) = tokio::sync::watch::channel(0);
    let cx = Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        notify_jobs,
        scheduler,
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = listener.local_addr().unwrap().to_string();
    drop(listener);
    let name = ZoneName::parse("example.com").unwrap();
    let caller = Caller::socket();
    let single = import_zone(
        &cx,
        &caller,
        &name,
        &ImportZoneRequest {
            content: None,
            from_server: Some(server.clone()),
            mode: "append".to_string(),
            dry_run: false,
            create: true,
        },
    )
    .await
    .unwrap_err();
    let catalog = import_zones(
        &cx,
        &caller,
        &ImportZonesRequest {
            from_server: server.clone(),
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
        (single, format!("AXFR from {server} failed")),
        (
            catalog,
            format!("AXFR of catalog catalog.example from {server} failed"),
        ),
    ] {
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        let source = error.source().unwrap();
        assert!(source.downcast_ref::<FetchZoneError>().is_some());
        assert_eq!(error.to_string(), format!("{context}: {source}"));
        let cause = source.source().unwrap().source().unwrap();
        assert!(matches!(
            cause.downcast_ref::<io::Error>(),
            Some(cause) if cause.kind() == io::ErrorKind::ConnectionRefused,
        ));
    }
    assert!(zone::list(&cx).await.unwrap().is_empty());
}

/// Zone names normalize and deduplicate in request order.
#[test]
fn normalize_zone_names_canonicalizes_and_drops_repeats() {
    let names = ["Example.COM.", "example.net", " example.com", "example.net"].map(str::to_string);

    let zones = normalize_zone_names(&names).unwrap();

    assert_eq!(
        zones,
        vec![
            ZoneName::parse("example.com").unwrap(),
            ZoneName::parse("example.net").unwrap(),
        ]
    );
}

/// Zone-name lists reject empty input and invalid names.
#[test]
fn normalize_zone_names_rejects_empty_list_and_bad_name() {
    let empty = normalize_zone_names(&[]).unwrap_err();
    assert_eq!(empty.code(), ErrorCode::InvalidInput);

    let root = normalize_zone_names(&["example.com".to_string(), ".".to_string()]).unwrap_err();
    assert_eq!(root.code(), ErrorCode::InvalidZoneField);
}
