use crate::common::TestContext;
use axum::http::StatusCode;
use bindizr::{database::get_record_repository, database::model::record::RecordType};

#[tokio::test]
async fn test_record_crud_operations() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    // Test GET /records (should have NS record)
    let (status, _) = ctx
        .make_request("GET", &format!("/records?zone_name={}", zone.name), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Test POST /records (create)
    let create_record_request = serde_json::json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": zone.name
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_name = body["record"]["name"].as_str().unwrap();
    let record_type = body["record"]["record_type"].as_str().unwrap();
    let record_id = body["record"]["id"].as_i64().unwrap();
    assert_eq!(record_name, "api");
    assert_eq!(record_type, "A");

    // Test GET /records/{record_id}
    let (status, body) = ctx
        .make_request("GET", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api");

    // Test POST /records with same name and same type (should succeed)
    let duplicate_record_request = serde_json::json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.201",
        "ttl": 1800,
        "zone_name": zone.name
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
        "zone_name": zone.name
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(different_type_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Test GET /records (with data)
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_name={}", zone.name), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 3);

    // Test PUT /records/{record_id} (update)
    let update_record_request = serde_json::json!({
        "name": "api-updated",
        "record_type": "A",
        "value": "192.168.1.202",
        "ttl": 3600
    });

    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}", record_id),
            Some(update_record_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let updated_name = body["record"]["name"].as_str().unwrap();
    assert_eq!(updated_name, "api-updated");
    assert_eq!(body["record"]["value"], "192.168.1.202");

    // Test DELETE /records/{record_id}
    let (status, _) = ctx
        .make_request("DELETE", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deletion
    let (status, _) = ctx
        .make_request("GET", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_single_record_operations_are_scoped_by_zone() {
    let ctx = TestContext::new().await;
    let first_zone = ctx.create_test_zone().await;
    let second_zone_name = "example.net";

    sqlx::query(
        r#"
        INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(second_zone_name)
    .bind("ns1.example.net")
    .bind("admin@example.net")
    .bind(3600)
    .bind(2023010101)
    .bind(7200)
    .bind(3600)
    .bind(604800)
    .bind(86400)
    .execute(&ctx.db_pool)
    .await
    .expect("Failed to insert second test zone");

    let mut second_record_id = None;
    for (zone_name, value) in [
        (first_zone.name.as_str(), "192.0.2.10"),
        (second_zone_name, "192.0.2.20"),
    ] {
        let create_record_request = serde_json::json!({
            "name": "shared",
            "record_type": "A",
            "value": value,
            "ttl": 1800,
            "zone_name": zone_name
        });

        let (status, body) = ctx
            .make_request("POST", "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        if zone_name == second_zone_name {
            second_record_id = Some(body["record"]["id"].as_i64().unwrap());
        }
    }

    let second_record_id = second_record_id.unwrap();

    let (status, body) = ctx
        .make_request("GET", &format!("/records/{}", second_record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["value"], "192.0.2.20");

    let (status, _) = ctx
        .make_request("DELETE", &format!("/records/{}", second_record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = ctx
        .make_request(
            "GET",
            &format!("/records?zone_name={}", first_zone.name),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["name"] == "shared" && record["value"] == "192.0.2.10")
    );

    let (status, _) = ctx
        .make_request("GET", &format!("/records/{}", second_record_id), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_record_value_matching_is_case_sensitive() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    for value in ["Token=ABC", "Token=abc"] {
        let create_record_request = serde_json::json!({
            "name": "case-sensitive",
            "record_type": "TXT",
            "value": value,
            "ttl": 1800,
            "zone_name": zone.name
        });

        let (status, _) = ctx
            .make_request("POST", "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let record = get_record_repository()
        .get(
            Some(zone.id),
            "case-sensitive",
            &RecordType::TXT,
            Some("Token=abc"),
            None,
            false,
        )
        .await
        .expect("Failed to query record")
        .expect("Expected case-sensitive record match");

    assert_eq!(record.value, "Token=abc");
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
            "zone_name": zone.name
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
        .make_request("GET", &format!("/records?zone_name={}", zone.name), None)
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
        "zone_name": zone.name
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
        "zone_name": zone.name
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
        "zone_name": zone.name
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cname_record_id = body["record"]["id"].as_i64().unwrap();

    // Try to create an A record with the same name as the CNAME (should fail)
    let a_record_request = serde_json::json!({
        "name": "cname-test",
        "record_type": "A",
        "value": "2.2.2.2",
        "ttl": 1800,
        "zone_name": zone.name
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
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}", cname_record_id),
            Some(update_cname_request),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
