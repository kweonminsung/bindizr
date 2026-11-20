use std::sync::Arc;

use bindizr_core::config::Config;
use bindizr_core::dns::message::{Name, Opcode, Rcode, Rtype};
use bindizr_core::dns::query;
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use bindizr_service::authorization::Caller;
use bindizr_service::types::CreateTsigKeyRequest;
use bindizr_service::{Context, tsig_key};
use sqlx::SqliteConnection;
use tokio::sync::{mpsc, watch};

use super::*;

/// Verify that a malformed UPDATE retains FORMERR, but backend and key failures remain SERVFAIL.
#[tokio::test]
async fn questionless_update_does_not_hide_tsig_backend_failures() {
    use std::str::FromStr;

    use sqlx::Connection;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fault.sqlite");
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

    tsig_key::create(
        &cx,
        &Caller::socket(),
        &CreateTsigKeyRequest {
            name: "fault-key".to_string(),
            algorithm: None,
            secret: None,
            role_name: "admin".to_string(),
        },
    )
    .await
    .unwrap();
    let key = tsig_key::find_by_wire_name(&cx, "fault-key")
        .await
        .unwrap()
        .unwrap()
        .to_signing_key()
        .unwrap();

    let (_, request) = query::build_question(
        Opcode::UPDATE,
        false,
        false,
        &Name::<Vec<u8>>::from_str("example.com").unwrap(),
        Rtype::SOA,
        None,
    );
    let mut request = request.builder().additional();
    let verifier = tsig::sign_request(&mut request, key).unwrap();
    let query_data = request.finish();
    let dns_cx = DnsContext::new(cx.clone());
    let client_addr = "127.0.0.1:2136".parse::<SocketAddr>().unwrap();

    let response = handle_nsupdate_request(&dns_cx, client_addr, &query_data, ResponseLimit::UDP)
        .await
        .unwrap();

    assert_eq!(response[3] & 15, Rcode::FORMERR.to_int());
    tsig::verify_response(&verifier, &response).unwrap();

    let mut connection = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();

    for statement in ["UPDATE tsig_keys SET secret = ''", "DROP TABLE tsig_keys"] {
        sqlx::query(statement)
            .execute(&mut connection)
            .await
            .unwrap();
        let error = update::authenticate_tsig_key(&dns_cx, &query_data, "fault-key")
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            UpdateError::Tsig(TsigError::EmptySecret) | UpdateError::LoadTsigKey(_)
        ));

        let response =
            handle_nsupdate_request(&dns_cx, client_addr, &query_data, ResponseLimit::UDP)
                .await
                .unwrap();

        assert_eq!(response[3] & 15, Rcode::SERVFAIL.to_int());
    }

    let metrics = cx.metrics().encode();

    assert!(metrics.contains("bindizr_nsupdate_requests_total{result=\"formerr\"} 1\n"));
    assert!(metrics.contains("bindizr_nsupdate_requests_total{result=\"servfail\"} 2\n"));
}
