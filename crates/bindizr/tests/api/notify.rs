use crate::common::TestContext;
use axum::http::StatusCode;

#[tokio::test]
async fn test_notify_zone() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    let request = serde_json::json!({
        "zone_name": zone.name
    });
    let (status, body) = ctx
        .make_request("POST", "/notify/zones", Some(request))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        "NOTIFY sent successfully for zone: example.com"
    );
}

#[tokio::test]
async fn test_notify_all_zones() {
    let ctx = TestContext::new().await;
    ctx.create_test_zone().await;

    let request = serde_json::json!({
        "zone_name": null
    });
    let (status, body) = ctx
        .make_request("POST", "/notify/zones", Some(request))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "NOTIFY sent successfully for all zones");
}

#[tokio::test]
async fn test_notify_missing_zone_returns_not_found() {
    let ctx = TestContext::new().await;

    let request = serde_json::json!({
        "zone_name": "missing.example.com"
    });
    let (status, body) = ctx
        .make_request("POST", "/notify/zones", Some(request))
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("Zone not found: missing.example.com")
    );
}
