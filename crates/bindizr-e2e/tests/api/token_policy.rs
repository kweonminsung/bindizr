use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

fn authed_options() -> TestAppOptions {
    TestAppOptions {
        require_authentication: true,
        ..TestAppOptions::default()
    }
}

async fn create_zone(app: &TestApp, zone_name: &str) {
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "primary_ns": format!("ns1.{zone_name}"),
                "admin_email": "admin@example.com",
                "ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

fn record_body(zone_name: &str, name: &str, record_type: &str, value: &str) -> serde_json::Value {
    json!({
        "name": name,
        "record_type": record_type,
        "value": value,
        "zone_name": zone_name,
    })
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_sees_and_writes_only_granted_zones() {
    let mut app = TestApp::start_with_options(authed_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let granted_zone = app.zone_name("granted.com");
    let other_zone = app.zone_name("other.com");
    create_zone(&app, &granted_zone).await;
    create_zone(&app, &other_zone).await;

    // Persist a record in the ungranted zone so listing assertions can prove
    // exclusion, not pass over an empty zone.
    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(&other_zone, "app", "A", "192.0.2.9")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let ungranted_record_id = body["record"]["id"].as_i64().unwrap();

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "zone",
        "token-policy",
        "add",
        &granted_zone,
        "--token",
        &scoped_name,
    ])
    .await;

    app.set_auth_token(scoped_token);

    // Zone listing is filtered to grants; ungranted zones read as 404.
    let (status, body) = app.request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| z["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&granted_zone.as_str()));
    assert!(!names.contains(&other_zone.as_str()));
    assert_eq!(body["pagination"]["total"], json!(1));

    let (status, _) = app
        .request(Method::GET, &format!("/zones/{other_zone}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Record writes work in the granted zone and 403 elsewhere.
    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(&granted_zone, "app", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(&other_zone, "app", "A", "192.0.2.2")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");

    // Record listing only surfaces granted zones.
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?search={}&limit=1000", app.namespace()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let listed_ids: Vec<i64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_i64().unwrap())
        .collect();
    assert!(listed_ids.contains(&record_id));
    assert!(!listed_ids.contains(&ungranted_record_id));

    // The zone plane requires a global token.
    let new_zone = app.zone_name("new.com");
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": new_zone,
                "primary_ns": format!("ns1.{new_zone}"),
                "admin_email": "admin@example.com",
                "ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{granted_zone}"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // So does policy management (no self-escalation).
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{granted_zone}/token-policies"),
            Some(json!({ "api_token": scoped_name })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Records of ungranted zones are invisible even when addressed by id.
    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/records/{ungranted_record_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Deleting an own record still works.
    let (status, _) = app
        .request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_policies_enforce_name_patterns_and_types() {
    let mut app = TestApp::start_with_options(authed_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "zone",
        "token-policy",
        "add",
        &zone_name,
        "--token",
        &scoped_name,
        "--pattern",
        "*.dyn",
        "--types",
        "A,TXT",
    ])
    .await;

    app.set_auth_token(scoped_token);

    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "host.dyn", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Outside the name pattern.
    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "www", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Outside the type list.
    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(
                &zone_name,
                "host.dyn",
                "CNAME",
                "cdn.example.net",
            )),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_without_policies_sees_nothing() {
    let mut app = TestApp::start_with_options(authed_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;

    let (_, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, body) = app.request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pagination"]["total"], json!(0));

    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "app", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn global_token_policy_management_over_http() {
    let mut app = TestApp::start_with_options(authed_options()).await;
    let (global_name, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;
    let (scoped_name, _) = app.create_scoped_api_token().await;

    // Token names are unique.
    let output = app
        .run_cli(&["token", "create", "--name", &scoped_name])
        .await;
    assert!(!output.status.success());

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/token-policies"),
            Some(json!({ "api_token": scoped_name, "record_types": "A,AAAA" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let policy_id = body["token_policy"]["id"].as_i64().unwrap();
    assert_eq!(body["token_policy"]["record_types"], "A,AAAA");
    assert_eq!(body["token_policy"]["api_token"], json!(scoped_name));

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/token-policies"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_policies"].as_array().unwrap().len(), 1);

    // Policies cannot be attached to global tokens.
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/token-policies"),
            Some(json!({ "api_token": global_name })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/token-policies/{policy_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/token-policies"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["token_policies"].as_array().unwrap().is_empty());
}
