use std::sync::Arc;

use bindizr_core::config::Config;
use bindizr_core::dns::message::{Keepalive, Name, ParsedQuery, Rcode, Rtype};
use bindizr_core::dns::query;
use bindizr_core::metrics::Metrics;
use bindizr_db::Db;
use bindizr_service::Context;
use bindizr_service::error::ServiceError;
use bindizr_service::types::CreateTsigKeyRequest;
use sqlx::SqliteConnection;
use tokio::sync::{mpsc, watch};

use super::*;

/// Verify that grant-loading failures return a signed SERVFAIL.
#[tokio::test]
async fn transfer_authentication_signs_servfail_when_grant_loading_fails() {
    use std::error::Error;
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

    let (_, mut request) = query::build_question(
        Opcode::QUERY,
        false,
        false,
        &Name::<Vec<u8>>::from_str("example.com").unwrap(),
        Rtype::SOA,
        None,
    );
    let verifier = tsig::sign_request(&mut request, key).unwrap();
    let query_data = request.finish();
    let query = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();
    let dns_cx = DnsContext::new(cx);

    assert!(authenticate_tsig_key(&dns_cx, &query_data).await.is_ok());

    let mut connection = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    sqlx::query("DROP TABLE role_grants")
        .execute(&mut connection)
        .await
        .unwrap();
    let refusal = authenticate_tsig_key(&dns_cx, &query_data)
        .await
        .unwrap_err();

    assert!(refusal.is_failure());
    let source = refusal
        .source()
        .unwrap()
        .downcast_ref::<ServiceError>()
        .unwrap();

    assert!(source.source().is_some());
    let response = refusal
        .into_response(&QueryMetadata::from(&query), &query_data)
        .unwrap();

    assert_eq!(response[3] & 15, Rcode::SERVFAIL.to_int());
    tsig::verify_response(&verifier, &response).unwrap();
}
