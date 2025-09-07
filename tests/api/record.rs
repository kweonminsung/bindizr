use crate::common::TestContext;
use axum::http::StatusCode;

#[tokio::test]
async fn test_record_crud_operations() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    // Test GET /records (empty)
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["records"].as_array().unwrap().is_empty());

    // Test POST /records (create)
    let create_record_request = serde_json::json!({
        "name": "api.example.com",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_id": zone.id
    });

    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_id = body["record"]["id"].as_i64().unwrap();
    assert_eq!(body["record"]["name"], "api.example.com");
    assert_eq!(body["record"]["record_type"], "A");

    // Test GET /records/{id}
    let (status, body) = ctx
        .make_request("GET", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api.example.com");

    // Test GET /records (with data)
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);

    // Test PUT /records/{id} (update)
    let update_record_request = serde_json::json!({
        "name": "api-updated.example.com",
        "record_type": "A",
        "value": "192.168.1.201",
        "ttl": 3600,
        "zone_id": zone.id
    });

    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}", record_id),
            Some(update_record_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api-updated.example.com");
    assert_eq!(body["record"]["value"], "192.168.1.201");

    // Test DELETE /records/{id}
    let (status, _) = ctx
        .make_request("DELETE", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deletion
    let (status, _) = ctx
        .make_request("GET", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_record_history() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;
    let record = ctx.create_test_record(zone.id).await;

    // Test GET /records/{id}/history
    let (status, body) = ctx
        .make_request("GET", &format!("/records/{}/histories", record.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Should return history array (might be empty initially)
    assert!(body["record_histories"].as_array().is_some());
}

#[tokio::test]
async fn test_multiple_record_types() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    let record_types = vec![
        ("mail.example.com", "MX", "10 mail.example.com", Some(10)),
        (
            "_sip._tcp.example.com",
            "SRV",
            "10 5 5060 sip.example.com",
            Some(10),
        ),
        (
            "example.com",
            "TXT",
            "v=spf1 include:_spf.google.com ~all",
            None,
        ),
        ("ipv6.example.com", "AAAA", "2001:db8::1", None),
        ("alias.example.com", "CNAME", "www.example.com", None),
    ];

    for (name, record_type, value, priority) in record_types {
        let create_request = serde_json::json!({
            "name": name,
            "record_type": record_type,
            "value": value,
            "ttl": 3600,
            "priority": priority,
            "zone_id": zone.id
        });

        let (status, body) = ctx
            .make_request("POST", "/records", Some(create_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["record"]["record_type"], record_type);
        assert_eq!(body["record"]["value"], value);

        if let Some(expected_priority) = priority {
            assert_eq!(body["record"]["priority"], expected_priority);
        }
    }

    // Verify all records were created
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 5);
}
