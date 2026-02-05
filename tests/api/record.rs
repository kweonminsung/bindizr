use crate::common::TestContext;
use axum::http::StatusCode;

#[tokio::test]
async fn test_record_crud_operations() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    // Test GET /records (should have NS record)
    let (status, _) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Test POST /records (create)
    let create_record_request = serde_json::json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_name = body["record"]["name"].as_str().unwrap();
    let record_type = body["record"]["record_type"].as_str().unwrap();
    assert_eq!(record_name, "api");
    assert_eq!(record_type, "A");

    // Test GET /records/{name}/{record_type}
    let (status, body) = ctx
        .make_request(
            "GET",
            &format!("/records/{}/{}", record_name, record_type),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api");

    // Test POST /records with same name and same type (should succeed)
    let duplicate_record_request = serde_json::json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.201",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(duplicate_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Test POST /records with same name and different type (should succeed)
    let different_type_record_request = serde_json::json!({
        "name": "api",
        "record_type": "TXT",
        "value": "some text",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(different_type_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Test GET /records (with data)
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 3);

    // Test PUT /records/{name}/{record_type} (update)
    let update_record_request = serde_json::json!({
        "name": "api-updated",
        "record_type": "A",
        "value": "192.168.1.201",
        "ttl": 3600,
        "zone_id": zone.id
    });

    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}/{}", record_name, record_type),
            Some(update_record_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let updated_name = body["record"]["name"].as_str().unwrap();
    assert_eq!(updated_name, "api-updated");
    assert_eq!(body["record"]["value"], "192.168.1.201");

    // Test DELETE /records/{name}/{record_type}
    let (status, _) = ctx
        .make_request(
            "DELETE",
            &format!("/records/{}/{}", updated_name, record_type),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deletion
    let (status, _) = ctx
        .make_request(
            "GET",
            &format!("/records/{}/{}", updated_name, record_type),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_record_history() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;
    let record = ctx.create_test_record(zone.id).await;

    // Test GET /records/{name}/{record_type}/history
    let (status, body) = ctx
        .make_request(
            "GET",
            &format!(
                "/records/{}/{}/histories",
                record.name,
                record.record_type.to_string()
            ),
            None,
        )
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
        ("mail", "MX", "10 mail.example.com", Some(10)),
        ("_sip._tcp", "SRV", "10 5 5060 sip.example.com", Some(10)),
        ("@", "TXT", "v=spf1 include:_spf.google.com ~all", None),
        ("ipv6", "AAAA", "2001:db8::1", None),
        ("alias", "CNAME", "www.example.com", None),
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

#[tokio::test]
async fn test_cname_validation() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    // Create an A record
    let a_record_request = serde_json::json!({
        "name": "test",
        "record_type": "A",
        "value": "1.1.1.1",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Try to create a CNAME record with the same name (should fail)
    let cname_record_request = serde_json::json!({
        "name": "test",
        "record_type": "CNAME",
        "value": "other.example.com",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Create a CNAME record
    let cname_record_request = serde_json::json!({
        "name": "cname-test",
        "record_type": "CNAME",
        "value": "another.example.com",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cname_record_name = body["record"]["name"].as_str().unwrap();
    let cname_record_type = body["record"]["record_type"].as_str().unwrap();

    // Try to create an A record with the same name as the CNAME (should fail)
    let a_record_request = serde_json::json!({
        "name": "cname-test",
        "record_type": "A",
        "value": "2.2.2.2",
        "ttl": 1800,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Try to update the CNAME record to a different type (should fail because an A record with the same name exists)
    let update_cname_request = serde_json::json!({
        "name": "test",
        "record_type": "CNAME",
        "value": "updated.example.com",
        "ttl": 3600,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}/{}", cname_record_name, cname_record_type),
            Some(update_cname_request),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_prevent_default_records_creation() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    // Try to create an NS record (should fail)
    let ns_record_request = serde_json::json!({
        "name": "@",
        "record_type": "NS",
        "value": "ns1.example.com",
        "ttl": 3600,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(ns_record_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Try to create an A record to A type for the primary_ns (should fail)
    let a_record_request = serde_json::json!({
        "name": "ns1",
        "record_type": "A",
        "value": "1.1.1.1",
        "ttl": 3600,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_prevent_updating_to_default_records() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;
    let record = ctx.create_test_record(zone.id).await;

    // Try to update an existing record to NS type with name "@" (should fail)
    let update_ns_request = serde_json::json!({
        "name": "@",
        "record_type": "NS",
        "value": "ns1.example.com",
        "ttl": 3600,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request(
            "PUT",
            &format!(
                "/records/{}/{}",
                record.name,
                record.record_type.to_string()
            ),
            Some(update_ns_request),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Try to update an existing record to A type for the primary_ns (should fail)
    let update_a_request = serde_json::json!({
        "name": "ns1",
        "record_type": "A",
        "value": "1.1.1.1",
        "ttl": 3600,
        "zone_id": zone.id
    });
    let (status, _) = ctx
        .make_request(
            "PUT",
            &format!(
                "/records/{}/{}",
                record.name,
                record.record_type.to_string()
            ),
            Some(update_a_request),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
