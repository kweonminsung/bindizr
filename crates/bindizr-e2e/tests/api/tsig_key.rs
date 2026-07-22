use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

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
    let generated_secret = body["tsig_key"]["secret"].as_str().unwrap().to_string();
    assert!(!generated_secret.is_empty());

    // The generated secret is returned again on a single-key read...
    let (status, body) = app
        .request(Method::GET, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tsig_key"]["secret"], generated_secret.as_str());

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
                "secret": "bWktc2VjcmV0LWtleQ==",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_key"]["algorithm"], "hmac-sha512");
    assert_eq!(body["tsig_key"]["secret"], "bWktc2VjcmV0LWtleQ==");

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "bad-secret", "secret": "not base64!!" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

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

    // A global key already covers every zone, so zone policies are rejected.
    let zone_name = app.zone_name("global-key.example");
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "primary_ns": format!("ns1.{zone_name}"),
                "admin_email": "admin@test.com",
                "ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/tsig-policies"),
            Some(json!({ "tsig_key": "global-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A global key holds no policies, so it deletes without a guard.
    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/global-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/scoped-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_tsig_policy_lifecycle_and_delete_guard() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("tsig-zone.example");

    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "primary_ns": format!("ns1.{zone_name}"),
                "admin_email": "admin@test.com",
                "ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = app
        .request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "policy-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/tsig-policies"),
            Some(json!({
                "tsig_key": "policy-key",
                "record_name_pattern": "*.dyn",
                "record_types": "a,AAAA",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_policy"]["tsig_key"], "policy-key");
    assert_eq!(body["tsig_policy"]["record_name_pattern"], "*.dyn");
    assert_eq!(body["tsig_policy"]["record_types"], "A,AAAA");
    let policy_id = body["tsig_policy"]["id"].as_i64().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/tsig-policies"),
            Some(json!({ "tsig_key": "policy-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_policy"]["record_name_pattern"], "*");
    assert_eq!(body["tsig_policy"]["record_types"], "*");

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/tsig-policies"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tsig_policies"].as_array().unwrap().len(), 2);

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/tsig-policies"),
            Some(json!({ "tsig_key": "no-such-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/tsig-policies"),
            Some(json!({ "tsig_key": "policy-key", "record_name_pattern": "a*b" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/tsig-policies"),
            Some(json!({ "tsig_key": "policy-key", "record_types": "A,BOGUS" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The key cannot be deleted while policies reference it.
    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/policy-key", None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/tsig-policies/{policy_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Deleting the zone cascades its remaining policies, freeing the key.
    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::DELETE, "/tsig-keys/policy-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
}
