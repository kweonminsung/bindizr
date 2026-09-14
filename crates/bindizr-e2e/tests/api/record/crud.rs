use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify record creation, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_read_update_delete() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let create_record_request = json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": zone_name
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_id = body["record"]["id"].as_i64().unwrap();
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));
    assert_eq!(body["record"]["record_type"], "A");

    let (status, body) = app
        .request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    // The type filter parses at the service boundary, so junk is a 400
    // rather than an empty page.
    let (status, _) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=BOGUS"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let update_record_request = json!({
        "name": "api-updated",
        "record_type": "A",
        "value": "192.168.1.202",
        "ttl": 3600
    });
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(update_record_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], format!("api-updated.{zone_name}."));
    assert_eq!(body["record"]["value"], "192.168.1.202");

    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "ttl": 600 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["ttl"], 600);
    assert_eq!(body["record"]["name"], format!("api-updated.{zone_name}."));
    assert_eq!(body["record"]["value"], "192.168.1.202");

    let (status, _) = app
        .request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify zone-name normalization in record requests.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_normalize_zone_name() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("example.com");

    let create_zone_request = json!({
        "name": format!("{}.", zone_name.to_ascii_uppercase()),
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], zone_name);

    let create_record_request = json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": format!("{}.", zone_name.to_ascii_uppercase())
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));
    assert_eq!(body["record"]["zone_name"], format!("{zone_name}."));
}
