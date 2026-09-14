use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let bulk_request = json!({
        "zone_name": zone_name,
        "records": [
            { "name": "bulk1", "record_type": "A", "value": "192.0.2.1" },
            { "name": "bulk2", "record_type": "A", "value": "192.0.2.2", "ttl": 1800 },
            { "name": "bulkcname", "record_type": "CNAME", "value": "bulk1" },
            { "name": "@", "record_type": "MX", "value": "mail", "priority": 10 }
        ]
    });
    let (status, body) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["inserted"], 4);
    assert_eq!(body["records"].as_array().unwrap().len(), 4);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert_accepts_ds_ahead_of_its_delegation_ns() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let bulk_request = json!({
        "zone_name": zone_name,
        "records": [
            { "name": "sub", "record_type": "DS", "value": "12345 13 2 abababababababababababababababababababababababababababababababab" },
            { "name": "sub", "record_type": "NS", "value": "ns1.example.net." }
        ]
    });
    let (status, body) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["inserted"], 2);
    assert_eq!(body["records"][0]["record_type"], "DS");
    assert_eq!(body["records"][1]["record_type"], "NS");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_dry_run_rejects_a_ds_without_delegation_ns() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The commit-time delegation invariant only runs on apply, so the dry run
    // must reject the same batch itself to keep its validation promise.
    let bulk_request = json!({
        "zone_name": zone_name,
        "records": [
            { "name": "sub", "record_type": "DS", "value": "12345 13 2 abababababababababababababababababababababababababababababababab" }
        ],
        "dry_run": true
    });
    let (status, body) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("delegation NS"),
        "{body}"
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert_is_all_or_nothing() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The second record has an invalid type, so the whole batch must fail.
    let bulk_request = json!({
        "zone_name": zone_name,
        "records": [
            { "name": "ok", "record_type": "A", "value": "192.0.2.5" },
            { "name": "bad", "record_type": "NOPE", "value": "192.0.2.6" }
        ]
    });
    let (status, _) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Nothing from the failed batch should have been persisted.
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=ok"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert_unknown_zone_returns_not_found() {
    let app = TestApp::start().await;
    let missing_zone = app.zone_name("missing.example.com");

    let bulk_request = json!({
        "zone_name": missing_zone,
        "records": [ { "name": "a", "record_type": "A", "value": "192.0.2.1" } ]
    });
    let (status, _) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert_dry_run_then_apply() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let bulk_request = json!({
        "zone_name": zone_name,
        "records": [
            { "name": "dry1", "record_type": "A", "value": "192.0.2.40" },
            { "name": "dry2", "record_type": "A", "value": "192.0.2.41", "ttl": 1800 }
        ],
        "dry_run": true
    });
    let (status, body) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["inserted"], 0);
    assert_eq!(body["records"].as_array().unwrap().len(), 2);

    // The dry run must not have persisted anything.
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let bulk_request = json!({
        "zone_name": zone_name,
        "records": [
            { "name": "dry1", "record_type": "A", "value": "192.0.2.40" },
            { "name": "dry2", "record_type": "A", "value": "192.0.2.41", "ttl": 1800 }
        ]
    });
    let (status, body) = app
        .request(Method::POST, "/records/bulk", Some(bulk_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["applied"], true);
    assert_eq!(body["dry_run"], false);
    assert_eq!(body["inserted"], 2);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

// Rows hold one canonical spelling, so the filter has to reach it however the
// request spells the name.
