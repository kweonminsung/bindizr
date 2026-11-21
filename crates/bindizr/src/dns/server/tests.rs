use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bindizr_core::config::Config;
use bindizr_core::dns::message::{Keepalive, Opcode, Rtype};
use bindizr_core::dns::name::WireName;
use bindizr_core::dns::query;
use bindizr_core::metrics::Metrics;
use bindizr_core::model::transfer::TransferResult;
use bindizr_db::Db;
use bindizr_service::authorization::Caller;
use bindizr_service::types::{
    CreateRecordRequest, CreateSecondaryRequest, CreateZoneRequest, RecordValue, TransferLogFilter,
};
use bindizr_service::{Context, record, secondary, transfer, zone};
use sqlx::{Connection, SqliteConnection};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use super::*;
use crate::dns::stream::DnsStream;

/// Verify that a stored record's encoding failure retains its diagnostic cause
/// without copying the record value into the persisted transfer log.
#[tokio::test]
async fn transfer_log_excludes_record_values_when_encoding_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("transfer.sqlite");
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = path.to_str().unwrap().to_string();
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
    let zone_name = "private.example";

    zone::create(
        &cx,
        &caller,
        &CreateZoneRequest {
            name: zone_name.to_string(),
            mname: "ns1.private.example".to_string(),
            rname: "hostmaster@private.example".to_string(),
            default_ttl: None,
            serial: None,
            refresh: None,
            retry: None,
            expire: None,
            minimum_ttl: None,
            description: None,
            apex_ns: true,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    let response = record::create(
        &cx,
        &caller,
        &CreateRecordRequest {
            zone_name: zone_name.to_string(),
            name: "private".to_string(),
            record_type: "A".to_string(),
            value: RecordValue::Text("192.0.2.1".to_string()),
            ttl: None,
            priority: None,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    secondary::create(
        &cx,
        &caller,
        &CreateSecondaryRequest {
            name: "loopback".to_string(),
            address: "127.0.0.1".to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();

    // Fault injection reaches the encoder's invalid-stored-value branch;
    // ordinary record creation rejects this value before storing it.
    let marker = "private-record-value-marker";
    let mut connection = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    sqlx::query("UPDATE records SET value = ? WHERE id = ?")
        .bind(marker)
        .bind(response.record.id.unwrap())
        .execute(&mut connection)
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, client_addr) = listener.accept().await.unwrap();
    let (_reader, writer) = DnsStream::Tcp(stream).into_split();
    let (_, builder) = query::build_question(
        Opcode::QUERY,
        false,
        false,
        &WireName::from_str(zone_name).unwrap(),
        Rtype::AXFR,
        None,
    );
    let query_data = builder.finish();
    let query =
        ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(Duration::from_secs(30))).unwrap();

    let error = handle_tcp_xfr(
        &DnsContext::new(cx.clone()),
        &writer,
        client_addr,
        &query,
        &query_data,
    )
    .await
    .unwrap_err();

    assert!(error.to_string().contains(marker), "{error}");
    let logs = transfer::list(
        &cx,
        &caller,
        &TransferLogFilter {
            zone_name: Some(zone_name.to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(logs.items.len(), 1, "{logs:?}");
    assert_eq!(logs.items[0].result, TransferResult::Failed);
    let error = logs.items[0].error.as_deref().unwrap();

    assert!(
        !error.contains(marker),
        "record value reached the transfer log: {error}"
    );
    assert_eq!(error, "DNS_ENCODING_FAILED");
}
