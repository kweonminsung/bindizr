use crate::common::TestContext;
use axum::http::StatusCode;

#[tokio::test]
async fn test_zone_crud_operations() {
    let ctx = TestContext::new().await;

    // Test GET /zones (empty)
    let (status, body) = ctx.make_request("GET", "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["zones"].as_array().unwrap().is_empty());

    // Test POST /zones (create)
    let create_zone_request = serde_json::json!({
        "name": "test.com",
        "primary_ns": "ns1.test.com",
        "primary_ns_ip": "10.0.0.1",
        "admin_email": "admin.test.com",
        "ttl": 3600,
        "serial": 2023010101,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });

    let (status, body) = ctx
        .make_request("POST", "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let zone_id = body["zone"]["id"].as_i64().unwrap();
    assert_eq!(body["zone"]["name"], "test.com");

    // Verify that an NS record was automatically created for the zone
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "Expected one NS record to be created automatically");
    assert_eq!(records[0]["record_type"], "NS");
    assert_eq!(records[0]["name"], "@");
    assert_eq!(records[0]["value"], "ns1.test.com");

    // Test GET /zones/{id}
    let (status, body) = ctx
        .make_request("GET", &format!("/zones/{}", zone_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], "test.com");

    // Test GET /zones (with data)
    let (status, body) = ctx.make_request("GET", "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zones"].as_array().unwrap().len(), 1);

    // Test PUT /zones/{id} (update)
    let update_zone_request = serde_json::json!({
        "name": "updated-test.com",
        "primary_ns": "ns1.updated-test.com",
        "primary_ns_ip": "10.0.0.2",
        "admin_email": "admin.updated-test.com",
        "ttl": 7200,
        "serial": 2023010102,
        "refresh": 14400,
        "retry": 7200,
        "expire": 1209600,
        "minimum_ttl": 172800
    });

    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/zones/{}", zone_id),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], "updated-test.com");

    // Test DELETE /zones/{id}
    let (status, _) = ctx
        .make_request("DELETE", &format!("/zones/{}", zone_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deletion
    let (status, _) = ctx
        .make_request("GET", &format!("/zones/{}", zone_id), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_zone_rendered_output() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;
    let _record = ctx.create_test_record(zone.id).await;

    // Test GET /zones/{id}/rendered
    let (status, body) = ctx
        .make_request("GET", &format!("/zones/{}/rendered", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Should return rendered zone file content
    let content = body.as_str().unwrap();
    assert!(content.contains("example.com"));
    assert!(content.contains("SOA"));
    assert!(content.contains("NS"));
    assert!(content.contains("www.example.com"));
}

#[tokio::test]
async fn test_zone_history() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    // Test GET /zones/{id}/history
    let (status, body) = ctx
        .make_request("GET", &format!("/zones/{}/histories", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Should return history array (might be empty initially)
    assert!(body["zone_histories"].as_array().is_some());
}

#[tokio::test]
async fn test_ns_record_auto_creation() {
    let ctx = TestContext::new().await;

    // Create a zone
    let create_zone_request = serde_json::json!({
        "name": "autotest.com",
        "primary_ns": "ns1.autotest.com",
        "primary_ns_ip": "10.0.0.10",
        "admin_email": "admin.autotest.com",
        "ttl": 3600,
        "serial": 2023010101,
    });

    let (status, body) = ctx
        .make_request("POST", "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_id = body["zone"]["id"].as_i64().unwrap();

    // Verify NS record was automatically created
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "Expected exactly one NS record to be auto-created");
    
    let ns_record = &records[0];
    assert_eq!(ns_record["record_type"], "NS", "Auto-created record should be NS type");
    assert_eq!(ns_record["name"], "@", "NS record name should be @ (zone apex)");
    assert_eq!(ns_record["value"], "ns1.autotest.com", "NS record should point to primary_ns");
    assert_eq!(ns_record["zone_id"], zone_id);
}

