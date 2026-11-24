use std::sync::Arc;
use std::time::Duration;
use std::{env, slice};

use bindizr_core::config::{Config, DatabaseType};
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time;

use super::*;
use crate::authorization::Caller;
use crate::types::CreateZoneRequest;
use crate::{transaction, zone};

/// Create a catalog member through the zone service.
async fn create_member(cx: &Context, name: &str, serial: u32) -> ZoneName {
    let request = CreateZoneRequest {
        name: name.to_string(),
        mname: format!("ns.{name}"),
        rname: format!("hostmaster@{name}"),
        default_ttl: None,
        serial: Some(serial.into()),
        refresh: None,
        retry: None,
        expire: None,
        minimum_ttl: None,
        description: None,
        apex_ns: true,
        dry_run: false,
    };
    zone::create(cx, &Caller::socket(), &request).await.unwrap();
    ZoneName::parse(name).unwrap()
}

/// Verify that the second refresh reads newly committed membership only
/// after the first refresh releases the newly created catalog row.
#[tokio::test]
#[ignore = "requires a fresh PostgreSQL or MySQL database in BINDIZR_TEST_CATALOG_DB_URL"]
async fn overlapping_first_catalog_refreshes_read_members_under_lock() {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    let url = env::var("BINDIZR_TEST_CATALOG_DB_URL").unwrap();
    if url.starts_with("mysql:") {
        config.database.database_type = DatabaseType::MySql;
        config.database.mysql.url = url;
    } else {
        config.database.database_type = DatabaseType::Postgres;
        config.database.postgresql.url = url;
    }
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
    let first_member = create_member(&cx, "first.example", 42).await;
    let mut first_tx = cx.db().begin().await.unwrap();
    let (first_catalog, first_members) = refresh_catalog_tx(&mut first_tx, &cx).await.unwrap();
    assert_eq!(first_catalog.serial, Serial::from(42));
    assert_eq!(first_members, slice::from_ref(&first_member));

    let (started, ready) = oneshot::channel();
    let mut next_refresh = tokio::spawn({
        let cx = cx.clone();
        async move {
            let mut tx = cx.db().begin().await.unwrap();
            started.send(()).unwrap();
            let result = refresh_catalog_tx(&mut tx, &cx).await;
            transaction::finish_tx(tx, result, "failed to refresh catalog")
                .await
                .unwrap()
        }
    });
    ready.await.unwrap();
    assert!(
        time::timeout(Duration::from_millis(250), &mut next_refresh)
            .await
            .is_err()
    );
    let next_member = create_member(&cx, "next.example", 99).await;
    first_tx.commit().await.unwrap();
    let (next_catalog, next_members) = time::timeout(Duration::from_secs(5), next_refresh)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next_catalog.serial, Serial::from(43));
    assert_eq!(next_members, [first_member, next_member]);
}

/// Verify that the catalog digest changes when members change and is
/// indifferent to their order.
#[test]
fn catalog_digest_changes_only_with_membership() {
    let zone_names = |names: &[&str]| {
        names
            .iter()
            .map(|name| ZoneName::parse(name).unwrap())
            .collect::<Vec<_>>()
    };

    let original = catalog_digest(&zone_names(&["example.com", "test.com"]));

    assert_ne!(original, catalog_digest(&zone_names(&["example.com"])));

    // Order is not membership, so it must not read as a change.
    assert_eq!(
        original,
        catalog_digest(&zone_names(&["test.com", "example.com"]))
    );
}
