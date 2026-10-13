use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify TSIG key creation, retrieval, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_create_read_delete() {
    let app = TestApp::start().await;

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "role_name": "admin", "name": "update-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["tsig_key"]["name"], "update-key");
    assert_eq!(body["tsig_key"]["algorithm"], "hmac-sha256");
    let generated_secret = body["secret"].as_str().unwrap().to_string();
    assert!(!generated_secret.is_empty());

    // The generated secret is returned again on a single-key read...
    let (status, body) = app
        .send_request(Method::GET, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret"], generated_secret.as_str());

    // ...but omitted from the list response, which the compose stack's own
    // key may share.
    let (status, body) = app.send_request(Method::GET, "/tsig-keys", None).await;
    assert_eq!(status, StatusCode::OK);
    let listed = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["name"] == "update-key")
        .expect("the key is listed");
    assert!(listed.get("secret").is_none());

    let (status, _) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "role_name": "admin", "name": "update-key" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = app
        .send_request(Method::DELETE, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .send_request(Method::GET, "/tsig-keys/update-key", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify that TSIG key imports existing secret and algorithm.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_imports_existing_secret_and_algorithm() {
    let app = TestApp::start().await;

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({
                           "role_name": "admin",
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
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "role_name": "admin", "name": "bad-secret", "secret": "not base64!!" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Secrets under 16 decoded bytes are refused.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "role_name": "admin", "name": "short-secret", "secret": "c2VjcmV0" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // hmac-md5 is a valid TSIG algorithm on the wire (RFC 8945) but is
    // deliberately unsupported here.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "role_name": "admin", "name": "bad-alg", "algorithm": "hmac-md5" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify that a TSIG key names its role, which must exist.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_names_its_role() {
    let app = TestApp::start().await;

    let (status, _) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "roleless-key", "role_name": "no-such-role" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": "admin-key", "role_name": "admin" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["tsig_key"]["role_name"], "admin");

    let (status, body) = app.send_request(Method::GET, "/tsig-keys", None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["items"].as_array().unwrap();
    let key = keys.iter().find(|k| k["name"] == "admin-key").unwrap();
    assert_eq!(key["role_name"], "admin");

    let (status, _) = app
        .send_request(Method::DELETE, "/tsig-keys/admin-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
}
