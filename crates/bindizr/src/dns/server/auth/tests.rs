use std::{str::FromStr, sync::Arc};

use bindizr_core::{
    config::Config,
    dns::{
        message::{Keepalive, Name, Opcode, Rtype},
        query::build_question,
        tsig::{sign_request, verify_response},
    },
    metrics::Metrics,
};
use bindizr_service::{Context, types::CreateTsigKeyRequest};
use sqlx::Connection;

use super::*;

/// Grant-loading failures return a signed SERVFAIL.
#[tokio::test]
async fn transfer_authentication_signs_servfail_when_grant_loading_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fault.sqlite");
    let config_path = directory.path().join("bindizr.toml");
    std::fs::write(
        &config_path,
        format!(
            "[database]\ntype=\"sqlite\"\n[database.sqlite]\nfile_path=\"{}\"\n",
            path.display()
        ),
    )
    .unwrap();
    let config = Config::load(config_path.to_str().unwrap()).unwrap();
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
    let (_, mut request) = build_question(
        Opcode::QUERY,
        false,
        false,
        &Name::<Vec<u8>>::from_str("example.com").unwrap(),
        Rtype::SOA,
        None,
    );
    let client = sign_request(&mut request, key).unwrap();
    let request = request.finish();
    let query = ParsedQuery::parse(&request, Keepalive::None).unwrap();
    let dns_cx = DnsContext::new(cx);
    assert!(authenticate_tsig_key(&dns_cx, &request).await.is_ok());
    let mut connection = sqlx::SqliteConnection::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    sqlx::query("DROP TABLE role_grants")
        .execute(&mut connection)
        .await
        .unwrap();
    let failure = authenticate_tsig_key(&dns_cx, &request).await.unwrap_err();
    assert!(failure.is_failure());
    let response = failure.into_response(&query).unwrap();
    assert_eq!(response[3] & 15, 2);
    verify_response(&client, &response).unwrap();
}
