use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

async fn create_named_zone(app: &TestApp, zone_name: &str) {
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@test.com",
                "default_ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_grant_lifecycle_and_delete_guard() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("tsig-zone.example");
    create_named_zone(&app, &zone_name).await;

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "grant-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::POST,
            "/tsig-keys/grant-key/grants",
            Some(json!({
                "zone_name": zone_name,
                "record_name_pattern": "*.dyn",
                "record_types": "a,AAAA",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_grant"]["tsig_key"], "grant-key");
    assert_eq!(body["tsig_grant"]["zone_name"], json!(zone_name));
    assert_eq!(body["tsig_grant"]["record_name_pattern"], "*.dyn");
    assert_eq!(body["tsig_grant"]["record_types"], "A,AAAA");
    let grant_id = body["tsig_grant"]["id"].as_i64().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            "/tsig-keys/grant-key/grants",
            Some(json!({ "zone_name": zone_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_grant"]["record_name_pattern"], "*");
    assert_eq!(body["tsig_grant"]["record_types"], "*");

    // Both grants show from the key's side and from the zone's.
    let (status, body) = app
        .request(Method::GET, "/tsig-keys/grant-key/grants", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tsig_grants"].as_array().unwrap().len(), 2);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/tsig-grants"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tsig_grants"].as_array().unwrap().len(), 2);

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys/no-such-key/grants",
            Some(json!({ "zone_name": zone_name })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys/grant-key/grants",
            Some(json!({ "zone_name": zone_name, "record_name_pattern": "a*b" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys/grant-key/grants",
            Some(json!({ "zone_name": zone_name, "record_types": "A,BOGUS" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The key cannot be deleted while it still holds grants.
    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/grant-key", None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/tsig-keys/grant-key/grants/{grant_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Deleting the zone cascades its remaining grants, freeing the key.
    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/grant-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
}
