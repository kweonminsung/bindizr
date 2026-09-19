use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify that record delete matching moves the zone by one serial.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_matching_moves_the_zone_by_one_serial() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for address in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": "www", "type": "A", "value": address, "zone_name": zone_name
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "type": "TXT", "value": "keep", "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let serial_of = async |app: &TestApp| -> i64 {
        let (_, body) = app
            .send_request(Method::GET, &format!("/zones?name={zone_name}"), None)
            .await;
        body["items"][0]["serial"].as_i64().unwrap()
    };
    let before = serial_of(&app).await;

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=A&dry_run=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 3, "{body}");
    assert_eq!(body["applied"], false, "{body}");
    assert_eq!(serial_of(&app).await, before, "a dry run must not move it");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 3, "{body}");

    // Row by row would bump it three times and serve the half-removed RRset.
    assert_eq!(serial_of(&app).await, before + 1);

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    let kept: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kept,
        ["TXT"],
        "another type at the name is not every record of the name and type"
    );

    // Matching nothing leaves the zone where it is, so a retry is free.
    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], 0, "{body}");
    assert_eq!(serial_of(&app).await, before + 1);
}

/// Verify that record delete matching refuses what would widen it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_matching_refuses_what_would_widen_it() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The last would be a whole-zone delete; the other cannot be meant.
    for (query, expected) in [
        (
            format!("/records?zone_name={zone_name}&name=www&value=x"),
            "record_type is required",
        ),
        (format!("/records?zone_name={zone_name}"), "name"),
    ] {
        let (status, body) = app.send_request(Method::DELETE, &query, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert!(
            body["error"].as_str().unwrap().contains(expected),
            "{query}: {body}"
        );
    }
}

/// Verify that a TXT record goes by the value it was created with.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_matches_a_txt_value_as_the_content_it_was_created_with() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // These quotes are data, not delimiters, so the delete has to be given
    // the same string the create was.
    let value = "\"hello\"";
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "type": "TXT", "value": value, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=www&type=TXT&value=%22hello%22"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"].as_i64(), Some(1), "{body}");

    // Several character-strings are named the way a create names them, and
    // every one has to match: a subset names no record.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "seg", "type": "TXT", "value": ["hello", "world"],
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=seg&type=TXT&value=hello"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"].as_i64(), Some(0), "{body}");

    // A value naming no record removes none: reading the same string the other
    // way would delete whichever record that spelling happens to name.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "plain", "type": "TXT", "value": "hello", "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records?zone_name={zone_name}&name=plain&type=TXT&value=%22hello%22"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"].as_i64(), Some(0), "{body}");
}
