use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

/// Verify listing and retrieval of zone versions.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_versions_list_and_get() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let base_serial = zone["serial"].as_i64().unwrap();

    // serial +1: add record A; serial +2: add record B.
    let record_a = json!({
        "name": "www", "record_type": "A", "value": "192.0.2.50",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(record_a))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_b = json!({
        "name": "mail", "record_type": "A", "value": "192.0.2.51",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(record_b))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("missing version items");
    assert!(items.len() >= 2);
    let serials: Vec<i64> = items
        .iter()
        .map(|item| item["serial"].as_i64().unwrap())
        .collect();
    assert!(
        serials.windows(2).all(|pair| pair[0] > pair[1]),
        "versions must be newest first: {serials:?}"
    );
    assert_eq!(serials[0], base_serial + 2);
    assert!(items[0]["rname"].as_str().unwrap().contains('@'));

    let (status, page) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/versions?limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        page["items"][0]["serial"].as_i64().unwrap(),
        base_serial + 1
    );

    // At base_serial + 1 only record A existed.
    let (status, detail) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/{}", base_serial + 1),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        detail["version"]["serial"].as_i64().unwrap(),
        base_serial + 1
    );
    let a_records: Vec<&str> = detail["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["record_type"] == "A")
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(a_records, ["www"]);

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/999999"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "VERSION_NOT_FOUND");

    let missing_zone = app.zone_name("missing.example");
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones/{missing_zone}/versions"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
}

/// Verify that zone versions diff reports the records between two serials.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_versions_diff_reports_the_records_between_two_serials() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let base_serial = zone["serial"].as_i64().unwrap();

    for (name, value) in [("www", "192.0.2.80"), ("extra", "192.0.2.81")] {
        let (status, _) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "name": name, "record_type": "A", "value": value,
                    "ttl": 300, "zone_name": zone_name
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (status, diff) = app
        .send_request(
            Method::GET,
            &format!(
                "/zones/{zone_name}/versions/diff?from={}&to={}",
                base_serial,
                base_serial + 1
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        diff["diff"]["summary"],
        json!({ "added": 1, "removed": 0, "changed": 0 })
    );
    let added = &diff["diff"]["entries"][0];
    assert_eq!(added["change"], "added");
    assert_eq!(added["name"], format!("www.{zone_name}."));
    // The value is structured (display form), not a rendered rdata string.
    assert_eq!(added["to"][0]["value"], "192.0.2.80");

    // Omitting `to` compares against the current serial.
    let (status, diff) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/diff?from={base_serial}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(diff["to_serial"].as_i64().unwrap(), base_serial + 2);
    assert_eq!(diff["diff"]["summary"]["added"].as_i64().unwrap(), 2);
}

/// Verify that rollback previews match the applied changes.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rollback_dry_run_then_apply() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let keep_record = json!({
        "name": "keep", "record_type": "A", "value": "192.0.2.60",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(keep_record))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Capture the state to roll back to.
    let (_, zone_at_target) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    let target_serial = zone_at_target["zone"]["serial"].as_i64().unwrap();

    // Mutate past the target.
    let extra_record = json!({
        "name": "extra", "record_type": "A", "value": "192.0.2.61",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app
        .send_request(Method::POST, "/records", Some(extra_record))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let soa_update = json!({
        "name": zone_name,
        "mname": zone["mname"].as_str().unwrap(),
        "rname": "changed@example.com",
        "default_ttl": 7200
    });
    let (status, _) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(soa_update),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (_, current) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    let current_serial = current["zone"]["serial"].as_i64().unwrap();

    // Dry run: nothing applied.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/versions/{target_serial}/rollback?dry_run=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["summary"]["soa_changed"], true);
    let (_, after_dry) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(
        after_dry["zone"]["serial"].as_i64().unwrap(),
        current_serial
    );
    assert_eq!(after_dry["zone"]["default_ttl"].as_i64().unwrap(), 7200);

    // Real rollback: state returns to target, serial advances.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/versions/{target_serial}/rollback"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["target_serial"].as_i64().unwrap(), target_serial);
    assert_eq!(body["new_serial"].as_i64().unwrap(), current_serial + 1);

    let (_, restored) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(restored["zone"]["name"], zone_name);
    assert_eq!(
        restored["zone"]["serial"].as_i64().unwrap(),
        current_serial + 1
    );
    assert_eq!(restored["zone"]["default_ttl"].as_i64().unwrap(), 3600);
    assert_eq!(restored["zone"]["rname"], "admin@example.com");

    let (status, records) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=A"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = records["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].starts_with("keep."));
}

/// Verify that zone rollback restores a delegation NS and DS together.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rollback_restores_a_delegation_ns_and_ds_together() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for request in [
        json!({
            "name": "sub", "record_type": "NS", "value": "ns1.example.net.",
            "ttl": 3600, "zone_name": zone_name
        }),
        json!({
            "name": "sub", "record_type": "DS", "value": "12345 13 2 abababababababababababababababababababababababababababababababab",
            "ttl": 3600, "zone_name": zone_name
        }),
    ] {
        let (status, _) = app
            .send_request(Method::POST, "/records", Some(request))
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    let (_, zone_at_target) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    let target_serial = zone_at_target["zone"]["serial"].as_i64().unwrap();

    for record_type in ["DS", "NS"] {
        let (_, listing) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&record_type={record_type}&name=sub"),
                None,
            )
            .await;
        let id = listing["items"][0]["id"].as_i64().unwrap();
        let (status, _) = app
            .send_request(Method::DELETE, &format!("/records/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Restoring both at once must not depend on which validates first.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/versions/{target_serial}/rollback"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["records_added"], 2, "{body}");

    for record_type in ["NS", "DS"] {
        let (_, listing) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&record_type={record_type}&name=sub"),
                None,
            )
            .await;
        assert_eq!(
            listing["items"].as_array().unwrap().len(),
            1,
            "{record_type} not restored"
        );
    }
}

/// Verify that zone rollback rejects bad serials.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rollback_rejects_bad_serials() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let current_serial = zone["serial"].as_i64().unwrap();

    // Serials >= current and non-positive ones are invalid input; a serial in
    // the valid range that predates the first stored version is a 404.
    for (serial, expected_status, expected_code) in [
        (current_serial, StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (
            current_serial + 100,
            StatusCode::BAD_REQUEST,
            "INVALID_INPUT",
        ),
        (0, StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (-5, StatusCode::BAD_REQUEST, "INVALID_INPUT"),
        (
            current_serial - 1,
            StatusCode::NOT_FOUND,
            "VERSION_NOT_FOUND",
        ),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/versions/{serial}/rollback"),
                None,
            )
            .await;
        assert_eq!(status, expected_status, "serial {serial}");
        assert_eq!(body["code"], expected_code, "serial {serial}");
    }
}

/// Verify that zone versions record who made each change.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_versions_record_who_made_each_change() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        ..Default::default()
    })
    .await;
    let (token_name, token) = app.create_api_token().await;

    // Over the daemon socket, whose peer is the local daemon owner: no
    // credential stands behind it.
    let zone_name = app.zone_name("audit.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.set_auth_token(token);
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "record_type": "A", "value": "192.0.2.7",
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap();

    assert_eq!(items[0]["change_source"], "token", "{body}");
    assert_eq!(items[0]["changed_by"], token_name, "{body}");

    let created = items.last().unwrap();
    assert_eq!(created["change_source"], "local", "{body}");
    assert!(created["changed_by"].is_null(), "{body}");
}
