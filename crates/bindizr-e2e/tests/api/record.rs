use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_read_update_delete() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let create_record_request = json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": zone_name
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let record_id = body["record"]["id"].as_i64().unwrap();
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));
    assert_eq!(body["record"]["record_type"], "A");

    let (status, body) = app
        .request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
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
    assert_eq!(body["record"]["name"], format!("api-updated.{zone_name}."));
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
async fn record_normalize_zone_name() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("example.com");

    let create_zone_request = json!({
        "name": format!("{}.", zone_name.to_ascii_uppercase()),
        "primary_ns": format!("ns1.{zone_name}"),
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], zone_name);

    let create_record_request = json!({
        "name": "api",
        "record_type": "A",
        "value": "192.168.1.200",
        "ttl": 1800,
        "zone_name": format!("{}.", zone_name.to_ascii_uppercase())
    });
    let (status, body) = app
        .request(Method::POST, "/records", Some(create_record_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["record"]["name"], format!("api.{zone_name}."));
    assert_eq!(body["record"]["zone_name"], format!("{zone_name}."));
}

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
async fn record_scope_by_zone() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let first_zone_name = zone["name"].as_str().unwrap();
    let second_zone_name = app.zone_name("example.net");

    let second_zone = json!({
        "name": second_zone_name,
        "primary_ns": format!("ns1.{second_zone_name}"),
        "admin_email": "admin@example.net",
        "ttl": 3600
    });
    let (status, _) = app.request(Method::POST, "/zones", Some(second_zone)).await;
    assert_eq!(status, StatusCode::CREATED);

    let mut second_record_id = None;
    for (zone_name, value) in [
        (first_zone_name, "192.0.2.10"),
        (second_zone_name.as_str(), "192.0.2.20"),
    ] {
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
        if zone_name == second_zone_name {
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
        .request(
            Method::GET,
            &format!("/records?zone_name={first_zone_name}"),
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
                |record| record["name"] == format!("shared.{first_zone_name}.")
                    && record["value"] == "192.0.2.10"
            )
    );

    let (status, _) = app
        .request(Method::GET, &format!("/records/{second_record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_filter_and_paginate() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

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
            &format!("/records?zone_name={zone_name}&value=168.1&min_ttl=1000&max_ttl=2000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&search=mail&min_priority=5&max_priority=15"),
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
            &format!("/records?zone_name={zone_name}&value=target.example.com"),
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
            &format!("/records?zone_name={zone_name}.&name=api.{zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("api.{zone_name}."));

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&limit=1&offset=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records = body["items"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("api.{zone_name}."));
    assert_eq!(body["pagination"]["total"], 4);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 2);

    let (status, _) = app.request(Method::GET, "/records?offset=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_preserve_txt_segments_and_case() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

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
    assert_eq!(status, StatusCode::BAD_REQUEST);

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

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_supported_types() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

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
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
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
