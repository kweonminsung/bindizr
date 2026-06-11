use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn api_home_returns_running_message() {
    let app = TestApp::start().await;

    let (status, body) = app.request(Method::GET, "/", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["msg"], "bindizr API running");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn missing_resources_and_invalid_payloads_return_client_errors() {
    let app = TestApp::start().await;

    let (status, _) = app.request(Method::GET, "/zones/99999", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app.request(Method::GET, "/records/99999", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let invalid_zone = json!({ "name": "test.com" });
    let (status, _) = app
        .request(Method::POST, "/zones", Some(invalid_zone))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let zone = app.create_test_zone().await;
    let invalid_record = json!({
        "name": "test.example.com",
        "record_type": "INVALID",
        "value": "192.168.1.1",
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(invalid_record))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
