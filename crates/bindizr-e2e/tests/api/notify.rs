use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_zone_all_and_bump_serial() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let request = json!({ "zone_name": zone["name"] });
    let (status, body) = app
        .request(Method::POST, "/zones/notify", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name}")
    );

    let request = json!({ "zone_name": null });
    let (status, body) = app
        .request(Method::POST, "/zones/notify", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "NOTIFY sent successfully for all zones");

    let (status, before) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let before_serial = before["zone"]["serial"].as_i64().unwrap();

    // bump_serial makes secondaries transfer even when nothing changed.
    let request = json!({ "zone_name": zone_name, "bump_serial": true });
    let (status, body) = app
        .request(Method::POST, "/zones/notify", Some(request))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name} (serial bumped)")
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
        .request(Method::POST, "/zones/notify", Some(request))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(&format!("Zone with name '{missing_zone_name}' not found"))
    );
}

// The catalog zone is virtual: it has no row, so no zone grant can name it
// and a scoped token must not be able to notify it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_cannot_notify_the_catalog_zone() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        ..TestAppOptions::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let (_, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, _) = app
        .request(
            Method::POST,
            "/zones/notify",
            Some(json!({ "zone_name": "catalog.bind" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    app.set_auth_token(global_token);
    let (status, _) = app
        .request(
            Method::POST,
            "/zones/notify",
            Some(json!({ "zone_name": "catalog.bind" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}
