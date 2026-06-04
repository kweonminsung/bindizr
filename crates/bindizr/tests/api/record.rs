use axum::http::StatusCode;
use bindizr::{database::get_record_repository, dns, model::record::RecordType};

use crate::common::TestContext;

#[tokio::test]
async fn record_create_read_update_delete_round_trip() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

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
    assert_eq!(record_name, "api.example.com.");
    assert_eq!(record_type, "A");

    // Test GET /records/{record_id}
    let (status, body) = ctx
        .make_request("GET", &format!("/records/{}", record_id), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api.example.com.");

    // Test GET /records (with data)
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_name={}", zone.name), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

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
    assert_eq!(updated_name, "api-updated.example.com.");
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
async fn record_create_and_update_reject_invalid_address_and_cname_values() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    for (record_type, value, expected_error) in [
        ("A", "not-an-ip", "valid IPv4"),
        ("AAAA", "192.168.1.1", "valid IPv6"),
        (
            "CNAME",
            "bad target.example.com",
            "must not contain whitespace",
        ),
        (
            "CNAME",
            "-bad.example.com",
            "must not start or end with hyphens",
        ),
    ] {
        let request = serde_json::json!({
            "name": format!("bad-{}", record_type.to_ascii_lowercase()),
            "record_type": record_type,
            "value": value,
            "ttl": 1800,
            "zone_name": zone.name
        });

        let (status, body) = ctx.make_request("POST", "/records", Some(request)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains(expected_error),
            "unexpected error for {} value '{}': {}",
            record_type,
            value,
            body["error"]
        );
    }

    let valid_request = serde_json::json!({
        "name": "valid",
        "record_type": "A",
        "value": "192.0.2.10",
        "ttl": 1800,
        "zone_name": zone.name
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(valid_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();

    let invalid_update = serde_json::json!({
        "name": "valid",
        "record_type": "AAAA",
        "value": "not-ipv6",
        "ttl": 1800
    });
    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}", record_id),
            Some(invalid_update),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("valid IPv6"));
}

#[tokio::test]
async fn record_reads_are_scoped_to_their_zone() {
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
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |record| record["name"] == "shared.example.com." && record["value"] == "192.0.2.10"
            )
    );

    let (status, _) = ctx
        .make_request("GET", &format!("/records/{}", second_record_id), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn record_list_filters_support_ranges_search_and_pagination() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    for request in [
        serde_json::json!({
            "name": "api",
            "record_type": "A",
            "value": "192.168.1.200",
            "ttl": 1800,
            "zone_name": zone.name
        }),
        serde_json::json!({
            "name": "mail",
            "record_type": "MX",
            "value": "mail.example.com",
            "ttl": 3600,
            "priority": 10,
            "zone_name": zone.name
        }),
        serde_json::json!({
            "name": "alias",
            "record_type": "CNAME",
            "value": "Target.Example.Com",
            "ttl": 7200,
            "zone_name": zone.name
        }),
    ] {
        let (status, _) = ctx.make_request("POST", "/records", Some(request)).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, body) = ctx
        .make_request(
            "GET",
            &format!(
                "/records?zone_name={}&value=168.1&min_ttl=1000&max_ttl=2000",
                zone.name
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "api.example.com.");

    let (status, body) = ctx
        .make_request(
            "GET",
            &format!(
                "/records?zone_name={}&search=mail&min_priority=5&max_priority=15",
                zone.name
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record_type"], "MX");

    let (status, body) = ctx
        .make_request(
            "GET",
            &format!("/records?zone_name={}&value=target.example.com", zone.name),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record_type"], "CNAME");

    let (status, body) = ctx
        .make_request(
            "GET",
            "/records?zone_name=Example.Com.&name=api.example.com",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "api.example.com.");

    let (status, body) = ctx
        .make_request(
            "GET",
            &format!("/records?zone_name={}&limit=1&offset=1", zone.name),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "api.example.com.");
    assert_eq!(body["pagination"]["total"], 3);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 1);

    let (status, _) = ctx.make_request("GET", "/records?offset=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn txt_record_value_matching_is_case_sensitive() {
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
            Some(&dns::txt::encode_txt_segments(["Token=abc"]).unwrap()),
            None,
            false,
        )
        .await
        .expect("Failed to query record")
        .expect("Expected case-sensitive record match");

    assert_eq!(
        dns::txt::decode_raw_txt_value(&record.value),
        Some(dns::txt::DecodedTxtValue::String("Token=abc".to_string()))
    );
}

#[tokio::test]
async fn record_owner_names_normalize_and_reject_out_of_bailiwick_values() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    let create_record_request = serde_json::json!({
        "name": "a1",
        "record_type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone.name
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], "a1.example.com.");

    let in_bailiwick_duplicate = serde_json::json!({
        "name": "a1.example.com.",
        "record_type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone.name
    });
    let (status, _) = ctx
        .make_request("POST", "/records", Some(in_bailiwick_duplicate))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let in_bailiwick_different_value = serde_json::json!({
        "name": "a1.example.com",
        "record_type": "A",
        "value": "127.0.0.2",
        "ttl": 1800,
        "zone_name": zone.name
    });
    let (status, body) = ctx
        .make_request("POST", "/records", Some(in_bailiwick_different_value))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], "a1.example.com.");

    for name in [
        "a1.",
        "example.net.",
        "a1.example.net.",
        "other.com.",
        "a1.other.com.",
        "badexample.com.",
    ] {
        let out_of_bailiwick = serde_json::json!({
            "name": name,
            "record_type": "A",
            "value": "127.0.0.3",
            "ttl": 1800,
            "zone_name": zone.name
        });
        let (status, _) = ctx
            .make_request("POST", "/records", Some(out_of_bailiwick))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name} should be rejected");
    }

    let update_out_of_bailiwick = serde_json::json!({
        "name": "a1.",
        "record_type": "A",
        "value": "127.0.0.4",
        "ttl": 1800
    });
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, _) = ctx
        .make_request(
            "PUT",
            &format!("/records/{}", record_id),
            Some(update_out_of_bailiwick),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn txt_record_value_accepts_segment_array() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    let create_record_request = serde_json::json!({
        "name": "segmented",
        "record_type": "TXT",
        "value": ["a", "bc"],
        "ttl": 1800,
        "zone_name": zone.name
    });

    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["value"], serde_json::json!(["a", "bc"]));
}

#[tokio::test]
async fn txt_record_value_rejects_empty_segment_array() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;

    let create_record_request = serde_json::json!({
        "name": "empty-segment-list",
        "record_type": "TXT",
        "value": [],
        "ttl": 1800,
        "zone_name": zone.name
    });

    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("TXT record must contain at least one character-string")
    );
}

#[tokio::test]
async fn txt_record_string_value_auto_splits_when_longer_than_dns_character_string() {
    let ctx = TestContext::new().await;
    let zone = ctx.create_test_zone().await;
    let value = "a".repeat(300);

    let create_record_request = serde_json::json!({
        "name": "long-txt",
        "record_type": "TXT",
        "value": value,
        "ttl": 1800,
        "zone_name": zone.name
    });

    let (status, body) = ctx
        .make_request("POST", "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["record"]["value"],
        serde_json::json!(["a".repeat(255), "a".repeat(45)])
    );
}

#[tokio::test]
async fn creates_mx_srv_txt_aaaa_and_cname_records() {
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
        let expected_value = match record_type {
            "MX" => "10 mail.example.com.",
            "SRV" => "10 5 5060 sip.example.com.",
            "CNAME" => "www.example.com.",
            _ => value,
        };
        assert_eq!(body["record"]["value"], expected_value);

        if let Some(expected_priority) = priority {
            assert_eq!(body["record"]["priority"], expected_priority);
        }
    }

    // Verify all records were created
    let (status, body) = ctx
        .make_request("GET", &format!("/records?zone_name={}", zone.name), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn cname_owner_conflict_rules_reject_invalid_combinations() {
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
