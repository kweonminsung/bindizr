use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_zone_all_and_force() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let request = json!({ "zone_name": zone["name"] });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name}")
    );

    let request = json!({ "zone_name": null });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "NOTIFY sent successfully for all zones");

    let (status, before) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let before_serial = before["zone"]["serial"].as_i64().unwrap();

    let request = json!({ "zone_name": zone_name, "force": true });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name} (forced)")
    );

    let (status, after) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let after_serial = after["zone"]["serial"].as_i64().unwrap();
    assert!(after_serial > before_serial);

    let missing_zone_name = app.zone_name("missing.example.com");
    let request = json!({ "zone_name": missing_zone_name });
    let (status, body) = app
        .request(Method::POST, "/notify/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(&format!("Zone not found: {missing_zone_name}"))
    );
}
