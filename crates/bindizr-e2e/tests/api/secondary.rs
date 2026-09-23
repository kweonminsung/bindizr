use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify secondary registration, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_create_read_update_delete() {
    let app = TestApp::start().await;
    let name = format!("{}-ns2", app.namespace());

    // The address is stored with its port spelled out and lowercased, so one
    // server has one row whichever way it is written.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": name, "address": "NS2.Example.net" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["secondary"]["name"], name);
    assert_eq!(body["secondary"]["address"], "ns2.example.net:53");
    assert_eq!(body["secondary"]["enabled"], true);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": name, "address": "192.0.2.7" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "SECONDARY_CONFLICT");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": format!("{name}-again"), "address": "ns2.example.net:53" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "SECONDARY_CONFLICT");

    let (status, body) = app
        .send_request(Method::GET, &format!("/secondaries/{name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secondary"]["address"], "ns2.example.net:53");

    let (status, body) = app.send_request(Method::GET, "/secondaries", None).await;
    assert_eq!(status, StatusCode::OK);
    let listed = body["items"].as_array().unwrap();
    assert!(listed.iter().any(|item| item["name"] == name), "{body}");

    // A partial update keeps the fields it leaves out.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["secondary"]["enabled"], false);
    assert_eq!(body["secondary"]["address"], "ns2.example.net:53");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({ "address": "[2001:db8::7]:5300" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["secondary"]["address"], "[2001:db8::7]:5300");
    assert_eq!(body["secondary"]["enabled"], false);

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({ "address": "not a host" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, _) = app
        .send_request(Method::DELETE, &format!("/secondaries/{name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(Method::GET, &format!("/secondaries/{name}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "SECONDARY_NOT_FOUND");
}

/// Verify that a secondary name must be a plain identifier and its address a host[:port].
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_rejects_a_bad_name_or_address() {
    let app = TestApp::start().await;

    for (name, address) in [
        ("ns 2", "192.0.2.7"),
        ("ns2/eu", "192.0.2.7"),
        ("ns2", ""),
        ("ns2", "192.0.2.7:port"),
        ("ns2", "192.0.2.7:0"),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/secondaries",
                Some(json!({ "name": format!("{}-{name}", app.namespace()), "address": address })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{name:?} {address:?}: {body}"
        );
        assert_eq!(body["code"], "INVALID_INPUT");
    }
}
