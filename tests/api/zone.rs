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
        "primary_ns_ipv6": "2001:db8::1",
        "admin_email": "admin@test.com",
        "ttl": 3600,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });

    let (status, body) = ctx
        .make_request("POST", "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(zone_name, "test.com");

    // Test GET /zones/{name}
    let (status, body) = ctx
        .make_request("GET", &format!("/zones/{}", zone_name), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], "test.com");

    // Test GET /zones (with data)
    let (status, body) = ctx.make_request("GET", "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zones"].as_array().unwrap().len(), 1);

    // Test PUT /zones/{name} (update)
    let update_zone_request = serde_json::json!({
        "name": "updated-test.com",
        "primary_ns": "ns1.updated-test.com",
        "primary_ns_ip": "10.0.0.2",
        "primary_ns_ipv6": "2001:db8::2",
        "admin_email": "admin@updated-test.com",
        "ttl": 7200,
        "refresh": 14400,
        "retry": 7200,
        "expire": 1209600,
        "minimum_ttl": 172800
    });

    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/zones/{}", zone_name),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let updated_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(updated_zone_name, "updated-test.com");

    // Test DELETE /zones/{name}
    let (status, _) = ctx
        .make_request("DELETE", &format!("/zones/{}", updated_zone_name), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deletion
    let (status, _) = ctx
        .make_request("GET", &format!("/zones/{}", updated_zone_name), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Test creating a zone with only primary_ns_ip
    let create_zone_ip_only = serde_json::json!({
        "name": "ip-only.com",
        "primary_ns": "ns1.ip-only.com",
        "primary_ns_ip": "10.0.0.3",
        "admin_email": "admin@ip-only.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(create_zone_ip_only))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Test creating a zone with only primary_ns_ipv6
    let create_zone_ipv6_only = serde_json::json!({
        "name": "ipv6-only.com",
        "primary_ns": "ns1.ipv6-only.com",
        "primary_ns_ipv6": "2001:db8::3",
        "admin_email": "admin@ipv6-only.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(create_zone_ipv6_only))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Test creating a zone with neither primary_ns_ip nor primary_ns_ipv6 (should fail)
    let create_zone_no_ip = serde_json::json!({
        "name": "no-ip.com",
        "primary_ns": "ns1.no-ip.com",
        "admin_email": "admin@no-ip.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(create_zone_no_ip))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

