use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify that invalid record values are rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_invalid_values() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    for (record_type, value, expected_error) in [
        ("A", "not-an-ip", "valid IPv4"),
        ("AAAA", "192.168.1.1", "valid IPv6"),
        (
            "CNAME",
            "bad target.example.com",
            "must not contain whitespace",
        ),
        ("CNAME", "bad..example.com", "must not contain empty labels"),
    ] {
        let request = json!({
            "name": format!("bad-{}", record_type.to_ascii_lowercase()),
            "record_type": record_type,
            "value": value,
            "ttl": 1800,
            "zone_name": zone["name"]
        });

        let (status, body) = app.request(Method::POST, "/records", Some(request)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap().contains(expected_error),
            "unexpected error for {record_type} value '{value}': {}",
            body["error"]
        );
    }

    let valid_request = json!({
        "name": "valid",
        "record_type": "A",
        "value": "192.0.2.10",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(valid_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();

    let invalid_update = json!({
        "name": "valid",
        "record_type": "AAAA",
        "value": "not-ipv6",
        "ttl": 1800
    });
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(invalid_update),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("valid IPv6"));
}

/// Verify that records sharing an owner and type must use one TTL.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_mixed_ttl_for_one_name_and_type() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let first = json!({
        "name": "www",
        "record_type": "A",
        "value": "192.0.2.1",
        "ttl": 300,
        "zone_name": zone["name"]
    });
    let (status, _) = app.request(Method::POST, "/records", Some(first)).await;
    assert_eq!(status, StatusCode::CREATED);

    // RFC 2181, Section 5.2: one TTL per RRset.
    let differing_ttl = json!({
        "name": "www",
        "record_type": "A",
        "value": "192.0.2.2",
        "ttl": 600,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(differing_ttl))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["error"].as_str().unwrap().contains("share one TTL"),
        "unexpected error: {}",
        body["error"]
    );

    let matching_ttl = json!({
        "name": "www",
        "record_type": "A",
        "value": "192.0.2.2",
        "ttl": 300,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(matching_ttl))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A different type at the same owner name is a separate RRset.
    let other_rrset = json!({
        "name": "www",
        "record_type": "TXT",
        "value": "hello",
        "ttl": 600,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(other_rrset))
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// Verify rejection of negative TTLs on record creation and update.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_negative_ttl_on_create_and_update() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "neg",
                "record_type": "A",
                "value": "192.0.2.1",
                "ttl": -1,
                "zone_name": zone["name"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("TTL"), "{body}");

    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "neg",
                "record_type": "A",
                "value": "192.0.2.1",
                "zone_name": zone["name"]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "ttl": -1 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("TTL"), "{body}");
}

/// Verify rejection of priority on record types without a priority field.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_priority_on_types_without_one() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    for (record_type, value) in [
        ("A", "192.0.2.1"),
        ("AAAA", "2001:db8::1"),
        ("CNAME", "target.example.com"),
        ("TXT", "hello"),
        ("NS", "ns2.example.com"),
    ] {
        let request = json!({
            "name": if record_type == "NS" { "@" } else { "prio" },
            "record_type": record_type,
            "value": value,
            "ttl": 3600,
            "priority": 10,
            "zone_name": zone["name"]
        });
        let (status, body) = app.request(Method::POST, "/records", Some(request)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{record_type}");
        assert!(
            body["error"].as_str().unwrap().contains("priority"),
            "unexpected error for {record_type}: {}",
            body["error"]
        );
    }

    let mx = json!({
        "name": "@",
        "record_type": "MX",
        "value": "mail.example.com",
        "ttl": 3600,
        "priority": 10,
        "zone_name": zone["name"]
    });
    let (status, _) = app.request(Method::POST, "/records", Some(mx)).await;
    assert_eq!(status, StatusCode::CREATED);

    // An update is held to the same rule.
    let a = json!({
        "name": "prio",
        "record_type": "A",
        "value": "192.0.2.1",
        "ttl": 3600,
        "zone_name": zone["name"]
    });
    let (status, body) = app.request(Method::POST, "/records", Some(a)).await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "priority": 10 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap().contains("priority"),
        "{body}"
    );
}

/// Verify preservation of TXT segment boundaries and case.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_preserve_txt_segments_and_case() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // TXT comparison is byte-exact, so two values differing only in case must
    // coexist under one name instead of colliding as duplicates.
    for value in ["Token=ABC", "Token=abc"] {
        let create_record_request = json!({
            "name": "case-sensitive",
            "record_type": "TXT",
            "value": value,
            "ttl": 1800,
            "zone_name": zone["name"]
        });

        let (status, _) = app
            .request(Method::POST, "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&value=Token=abc"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["value"], "Token=abc");

    let segmented = json!({
        "name": "segmented",
        "record_type": "TXT",
        "value": ["a", "bc"],
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app.request(Method::POST, "/records", Some(segmented)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["value"], json!(["a", "bc"]));

    let empty_segments = json!({
        "name": "empty-segment-list",
        "record_type": "TXT",
        "value": [],
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(empty_segments))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("TXT record must contain at least one character-string")
    );

    // A DNS character-string holds at most 255 octets (RFC 1035, Section 3.3), so a
    // 300-char value must be stored split into 255 + 45.
    let long_txt = json!({
        "name": "long-txt",
        "record_type": "TXT",
        "value": "a".repeat(300),
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app.request(Method::POST, "/records", Some(long_txt)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        body["record"]["value"],
        json!(["a".repeat(255), "a".repeat(45)])
    );
}

/// Verify owner normalization and rejection of names outside the zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_normalize_owner_and_reject_out_of_zone() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let create_record_request = json!({
        "name": "a1",
        "record_type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("a1.{zone_name}."));

    // The FQDN spelling resolves to the same stored owner as the relative
    // "a1" above, so it must be detected as a duplicate.
    let in_bailiwick_duplicate = json!({
        "name": format!("a1.{zone_name}."),
        "record_type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(in_bailiwick_duplicate))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let in_bailiwick_different_value = json!({
        "name": format!("a1.{zone_name}"),
        "record_type": "A",
        "value": "127.0.0.2",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(in_bailiwick_different_value))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("a1.{zone_name}."));

    for name in [
        "a1.",
        "example.net.",
        "a1.example.net.",
        "other.com.",
        "a1.other.com.",
        "badexample.com.",
    ] {
        let out_of_bailiwick = json!({
            "name": name,
            "record_type": "A",
            "value": "127.0.0.3",
            "ttl": 1800,
            "zone_name": zone["name"]
        });
        let (status, _) = app
            .request(Method::POST, "/records", Some(out_of_bailiwick))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name} should be rejected");
    }

    let update_out_of_bailiwick = json!({
        "name": "a1.",
        "record_type": "A",
        "value": "127.0.0.4",
        "ttl": 1800
    });
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (status, _) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(update_out_of_bailiwick),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify creation of every supported user record type.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_supported_types() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let record_types = vec![
        ("mail", "MX", "mail.example.com", Some(10)),
        ("_sip._tcp", "SRV", "5 5060 sip.example.com", Some(10)),
        ("@", "TXT", "v=spf1 include:_spf.google.com ~all", None),
        ("ipv6", "AAAA", "2001:db8::1", None),
        ("alias", "CNAME", "www.example.com", None),
        ("@", "CAA", "0 ISSUE letsencrypt.org", None),
        (
            "ssh",
            "SSHFP",
            "4 2 abababababababababababababababababababababababababababababababab",
            None,
        ),
        (
            "_443._tcp",
            "TLSA",
            "3 1 1 abababababababababababababababababababababababababababababababab",
            None,
        ),
    ];

    for (name, record_type, value, priority) in record_types {
        let create_request = json!({
            "name": name,
            "record_type": record_type,
            "value": value,
            "ttl": 3600,
            "priority": priority,
            "zone_name": zone["name"]
        });

        let (status, body) = app
            .request(Method::POST, "/records", Some(create_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["record"]["record_type"], record_type);
        let expected_value = match record_type {
            "MX" => "mail.example.com.",
            "SRV" => "5 5060 sip.example.com.",
            "CNAME" => "www.example.com.",
            "CAA" => "0 issue \"letsencrypt.org\"",
            "SSHFP" => "4 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            "TLSA" => "3 1 1 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            _ => value,
        };
        assert_eq!(body["record"]["value"], expected_value);

        if let Some(expected_priority) = priority {
            assert_eq!(body["record"]["priority"], expected_priority);
        }
    }

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    // 8 created here + the apex NS record auto-created with the zone.
    assert_eq!(records.len(), 9);
    for record_type in ["MX", "SRV", "TXT", "AAAA", "CNAME", "CAA", "SSHFP", "TLSA"] {
        assert!(
            records
                .iter()
                .any(|record| record["record_type"] == record_type),
            "expected {record_type} record in list"
        );
    }
}

/// Verify rejection of records that conflict with a CNAME.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_cname_conflicts() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let a_record_request = json!({
        "name": "test",
        "record_type": "A",
        "value": "1.1.1.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let cname_record_request = json!({
        "name": "test",
        "record_type": "CNAME",
        "value": "other.example.com",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let cname_record_request = json!({
        "name": "cname-test",
        "record_type": "CNAME",
        "value": "another.example.com",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(cname_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let cname_record_id = body["record"]["id"].as_i64().unwrap();

    let a_record_request = json!({
        "name": "cname-test",
        "record_type": "A",
        "value": "2.2.2.2",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(a_record_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Renaming the CNAME onto an owner that already holds an A record must
    // hit the same exclusivity check through the update path.
    let update_cname_request = json!({
        "name": "test",
        "record_type": "CNAME",
        "value": "updated.example.com",
        "ttl": 3600
    });
    let (status, _) = app
        .request(
            Method::PUT,
            &format!("/records/{cname_record_id}"),
            Some(update_cname_request),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
