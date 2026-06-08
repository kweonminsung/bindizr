use axum::http::StatusCode;

use crate::common::TestContext;

#[tokio::test]
async fn notify_zone_returns_success_for_existing_zone() {
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
async fn notify_all_zones_returns_success_when_zones_exist() {
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
async fn force_notify_increments_zone_serial() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    let request = serde_json::json!({
        "zone_name": zone.name,
        "force": true
    });
    let (status, body) = ctx
        .make_request("POST", "/notify/zones", Some(request))
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        "NOTIFY sent successfully for zone: example.com (forced)"
    );

    let serial: i32 = sqlx::query_scalar("SELECT serial FROM zones WHERE id = ?")
        .bind(zone.id)
        .fetch_one(&ctx.db_pool)
        .await
        .expect("failed to fetch zone serial");

    assert!(serial > zone.serial);
}

#[tokio::test]
async fn notify_missing_zone_returns_not_found() {
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
