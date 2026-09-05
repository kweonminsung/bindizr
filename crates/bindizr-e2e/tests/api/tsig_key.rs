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
async fn tsig_key_create_read_delete() {
    let app = TestApp::start().await;

    let (status, body) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "update-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_key"]["name"], "update-key");
    assert_eq!(body["tsig_key"]["algorithm"], "hmac-sha256");
    let generated_secret = body["secret"].as_str().unwrap().to_string();
    assert!(!generated_secret.is_empty());

    // The generated secret is returned again on a single-key read...
    let (status, body) = app
        .request(Method::GET, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret"], generated_secret.as_str());

    // ...but omitted from the list response.
    let (status, body) = app.request(Method::GET, "/tsig-keys", None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["tsig_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].get("secret").is_none());

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "update-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::GET, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_imports_existing_secret_and_algorithm() {
    let app = TestApp::start().await;

    let (status, body) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({
                "name": "imported-key",
                "algorithm": "hmac-sha512",
                "secret": "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_key"]["algorithm"], "hmac-sha512");
    assert_eq!(
        body["secret"],
        "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU="
    );

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "bad-secret", "secret": "not base64!!" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Secrets under 16 decoded bytes are refused.
    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "short-secret", "secret": "c2VjcmV0" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // hmac-md5 is a valid TSIG algorithm on the wire (RFC 8945) but is
    // deliberately unsupported here.
    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "bad-alg", "algorithm": "hmac-md5" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn global_tsig_key_lifecycle() {
    let app = TestApp::start().await;

    let (status, body) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "global-key", "global": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_key"]["global"], true);

    let (status, body) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "scoped-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_key"]["global"], false);

    let (status, body) = app.request(Method::GET, "/tsig-keys", None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["tsig_keys"].as_array().unwrap();
    let global = keys.iter().find(|k| k["name"] == "global-key").unwrap();
    assert_eq!(global["global"], true);

    // A global key already covers every zone, so it cannot be granted one.
    let zone_name = app.zone_name("global-key.example");
    create_named_zone(&app, &zone_name).await;

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys/global-key/grants",
            Some(json!({ "zone_name": zone_name })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A global key holds no grants, so it deletes without a guard.
    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/global-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/scoped-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
}
