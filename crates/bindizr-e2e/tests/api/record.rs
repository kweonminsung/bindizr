use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_read_update_delete_round_trip() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let create_record_request = json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_id = body["record"]["id"].as_i64().unwrap();
    assert_eq!(body["record"]["name"], "api.example.com.");
    assert_eq!(body["record"]["record_type"], "A");

    let (status, body) = app
        .request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api.example.com.");

    let (status, body) = app
        .request(
            Method::GET,
            "/records?zone_name=example.com&record_type=A",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    let update_record_request = json!({
        "name": "api-updated",
        "record_type": "A",
        "value": "192.168.1.202",
        "ttl": 3600
    });
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(update_record_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], "api-updated.example.com.");
    assert_eq!(body["record"]["value"], "192.168.1.202");

    let (status, _) = app
        .request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_normalizes_zone_name_for_lookup() {
    let app = TestApp::start().await;

    let create_zone_request = json!({
        "name": "Example.Com.",
        "primary_ns": "ns1.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], "example.com");

    let create_record_request = json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": "Example.Com."
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], "api.example.com.");
    assert_eq!(body["record"]["zone_name"], "example.com.");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_and_update_reject_invalid_address_and_cname_values() {
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
        (
            "CNAME",
            "-bad.example.com",
            "must not start or end with hyphens",
        ),
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

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reads_are_scoped_to_their_zone() {
    let app = TestApp::start().await;
    app.create_test_zone().await;

    let second_zone = json!({
        "name": "example.net",
        "primary_ns": "ns1.example.net",
        "admin_email": "admin@example.net",
        "ttl": 3600
    });
    let (status, _) = app.request(Method::POST, "/zones", Some(second_zone)).await;
    assert_eq!(status, StatusCode::CREATED);

    let mut second_record_id = None;
    for (zone_name, value) in [("example.com", "192.0.2.10"), ("example.net", "192.0.2.20")] {
        let create_record_request = json!({
            "name": "shared",
            "record_type": "A",
            "value": value,
            "ttl": 1800,
            "zone_name": zone_name
        });

        let (status, body) = app
            .request(Method::POST, "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
        if zone_name == "example.net" {
            second_record_id = Some(body["record"]["id"].as_i64().unwrap());
        }
    }

    let second_record_id = second_record_id.unwrap();

    let (status, body) = app
        .request(Method::GET, &format!("/records/{second_record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["value"], "192.0.2.20");

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/records/{second_record_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(Method::GET, "/records?zone_name=example.com", None)
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

    let (status, _) = app
        .request(Method::GET, &format!("/records/{second_record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_list_filters_support_ranges_search_and_pagination() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    for request in [
        json!({
            "name": "api",
            "record_type": "A",
            "value": "192.168.1.200",
            "ttl": 1800,
            "zone_name": zone["name"]
        }),
        json!({
            "name": "mail",
            "record_type": "MX",
            "value": "mail.example.com",
            "ttl": 3600,
            "priority": 10,
            "zone_name": zone["name"]
        }),
        json!({
            "name": "alias",
            "record_type": "CNAME",
            "value": "Target.Example.Com",
            "ttl": 7200,
            "zone_name": zone["name"]
        }),
    ] {
        let (status, _) = app.request(Method::POST, "/records", Some(request)).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, body) = app
        .request(
            Method::GET,
            "/records?zone_name=example.com&value=168.1&min_ttl=1000&max_ttl=2000",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "api.example.com.");

    let (status, body) = app
        .request(
            Method::GET,
            "/records?zone_name=example.com&search=mail&min_priority=5&max_priority=15",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record_type"], "MX");

    let (status, body) = app
        .request(
            Method::GET,
            "/records?zone_name=example.com&value=target.example.com",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["record_type"], "CNAME");

    let (status, body) = app
        .request(
            Method::GET,
            "/records?zone_name=Example.Com.&name=api.example.com",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "api.example.com.");

    let (status, body) = app
        .request(
            Method::GET,
            "/records?zone_name=example.com&limit=1&offset=2",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "api.example.com.");
    assert_eq!(body["pagination"]["total"], 4);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 2);

    let (status, _) = app.request(Method::GET, "/records?offset=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn txt_record_values_round_trip_and_filter_case_sensitively() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

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
            "/records?zone_name=example.com&value=Token=abc",
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

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_owner_names_normalize_and_reject_out_of_bailiwick_values() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

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
    assert_eq!(body["record"]["name"], "a1.example.com.");

    let in_bailiwick_duplicate = json!({
        "name": "a1.example.com.",
        "record_type": "A",
        "value": "127.0.0.1",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, _) = app
        .request(Method::POST, "/records", Some(in_bailiwick_duplicate))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let in_bailiwick_different_value = json!({
        "name": "a1.example.com",
        "record_type": "A",
        "value": "127.0.0.2",
        "ttl": 1800,
        "zone_name": zone["name"]
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(in_bailiwick_different_value))
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

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn creates_mx_srv_txt_aaaa_and_cname_records() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;

    let record_types = vec![
        ("mail", "MX", "10 mail.example.com", Some(10)),
        ("_sip._tcp", "SRV", "10 5 5060 sip.example.com", Some(10)),
        ("@", "TXT", "v=spf1 include:_spf.google.com ~all", None),
        ("ipv6", "AAAA", "2001:db8::1", None),
        ("alias", "CNAME", "www.example.com", None),
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

    let (status, body) = app
        .request(Method::GET, "/records?zone_name=example.com", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 6);
    for record_type in ["MX", "SRV", "TXT", "AAAA", "CNAME"] {
        assert!(
            records
                .iter()
                .any(|record| record["record_type"] == record_type),
            "expected {record_type} record in list"
        );
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn cname_owner_conflict_rules_reject_invalid_combinations() {
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
    assert_eq!(status, StatusCode::BAD_REQUEST);

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
    assert_eq!(status, StatusCode::BAD_REQUEST);

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
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
