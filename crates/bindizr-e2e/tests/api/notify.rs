use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_handlers_succeed_without_secondary_servers() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let request = json!({ "zone_name": zone["name"] });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        "NOTIFY sent successfully for zone: example.com"
    );

    let request = json!({ "zone_name": null });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "NOTIFY sent successfully for all zones");

    let (status, before) = app.request(Method::GET, "/zones/example.com", None).await;
    assert_eq!(status, StatusCode::OK);
    let before_serial = before["zone"]["serial"].as_i64().unwrap();

    let request = json!({ "zone_name": "example.com", "force": true });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        "NOTIFY sent successfully for zone: example.com (forced)"
    );

    let (status, after) = app.request(Method::GET, "/zones/example.com", None).await;
    assert_eq!(status, StatusCode::OK);
    let after_serial = after["zone"]["serial"].as_i64().unwrap();
    assert!(after_serial > before_serial);

    let request = json!({ "zone_name": "missing.example.com" });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("Zone not found: missing.example.com")
    );
}
