use std::{str::FromStr, sync::Arc};

use bindizr_core::{
    config::Config,
    dns::{
        message::{Name, Opcode, Rcode, Rtype},
        query::build_question,
        tsig::{TsigError, sign_request, verify_response},
    },
    metrics::Metrics,
};
use bindizr_service::{Context, authorization::Caller, tsig_key, types::CreateTsigKeyRequest};
use sqlx::Connection;

use super::*;

/// A malformed UPDATE retains FORMERR, but backend and key failures remain SERVFAIL.
#[tokio::test]
async fn questionless_update_does_not_hide_tsig_backend_failures() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fault.sqlite");
    let config: Config = serde_json::from_value(serde_json::json!({
        "database": { "sqlite": { "file_path": path.to_str().unwrap() } },
    }))
    .unwrap();
    let db = bindizr_db::Db::connect(&config.database).await.unwrap();
    let (notify_jobs, _jobs) = tokio::sync::mpsc::unbounded_channel();
    let (scheduler, _period) = tokio::sync::watch::channel(0);
    let cx = Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        notify_jobs,
        scheduler,
    ));
    tsig_key::create(
        &cx,
        &Caller::socket(),
        &CreateTsigKeyRequest {
            name: "fault-key".into(),
            role_name: "admin".into(),
            algorithm: None,
            secret: None,
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
    let (_, request) = build_question(
        Opcode::UPDATE,
        false,
        false,
        &Name::<Vec<u8>>::from_str("example.com").unwrap(),
        Rtype::SOA,
        None,
    );
    let mut request = request.builder().additional();
    let verifier = sign_request(&mut request, key).unwrap();
    let request = request.finish();
    let dns_cx = DnsContext::new(cx.clone());
    let client = "127.0.0.1:2136".parse().unwrap();

    let response = handle_nsupdate_request(
        &dns_cx,
        &request,
        client,
        TransferTransport::Udp,
        ResponseLimit::UDP,
    )
    .await
    .unwrap();
    assert_eq!(response[3] & 15, Rcode::FORMERR.to_int());
    verify_response(&verifier, &response).unwrap();

    let mut connection = sqlx::SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    for statement in ["UPDATE tsig_keys SET secret = ''", "DROP TABLE tsig_keys"] {
        sqlx::query(statement)
            .execute(&mut connection)
            .await
            .unwrap();
        let failure = update::authenticate_tsig_key(&dns_cx, "fault-key", &request)
            .await
            .unwrap_err();
        assert!(matches!(
            failure,
            update::UpdateError::Tsig(TsigError::EmptySecret) | update::UpdateError::LoadTsigKey(_),
        ));
        let response = handle_nsupdate_request(
            &dns_cx,
            &request,
            client,
            TransferTransport::Udp,
            ResponseLimit::UDP,
        )
        .await
        .unwrap();
        assert_eq!(response[3] & 15, Rcode::SERVFAIL.to_int());
    }
    let metrics = cx.metrics().encode();
    assert!(metrics.contains("bindizr_nsupdate_requests_total{result=\"formerr\"} 1\n"));
    assert!(metrics.contains("bindizr_nsupdate_requests_total{result=\"servfail\"} 2\n"));
}
