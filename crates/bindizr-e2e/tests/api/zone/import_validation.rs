//! Zone-file import validation, including conflicts with database-only records.
//! Append cases exercise those conflicts because imports load only rows whose
//! owner names occur in the submitted file.

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::TestApp;

/// Populate a zone with records before testing import validation.
async fn seed_records(app: &TestApp, zone_name: &str, records: Value) {
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records/bulk",
            Some(json!({ "zone_name": zone_name, "records": records })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// Verify that zone import passes over unsupported types only when asked.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_passes_over_unsupported_types_only_when_asked() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A real BIND zone file carries types bindizr does not store.
    let content = "www IN A 192.0.2.1\nbox IN HINFO \"amd64\" \"linux\"\n";

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["applied"], false, "{body}");
    assert!(
        body["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("HINFO")),
        "{body}"
    );

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "skip_unsupported": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true, "{body}");
    assert!(body["errors"].as_array().unwrap().is_empty(), "{body}");
    assert_eq!(body["summary"]["skipped"], 1, "{body}");
    assert!(
        body["skipped_records"][0]
            .as_str()
            .unwrap()
            .contains("HINFO"),
        "{body}"
    );

    // The supported line still landed.
    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
}

/// Verify that zone import zone file reports validation errors.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_reports_validation_errors() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A CNAME cannot coexist with another record of the same name.
    let content = "dup IN A 192.0.2.1\ndup IN CNAME www\n";
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    // Nothing applied because of the validation error.
    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=dup"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

/// Verify that zone import preview shows empty diff on validation error.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_preview_shows_empty_diff_on_validation_error() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A CNAME that can't coexist with the A fails the whole import, so the dry-run
    // preview must report the error with an empty diff, not a never-applied add.
    let content = "dup IN A 192.0.2.1\ndup IN CNAME www\n";
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert!(!body["errors"].as_array().unwrap().is_empty());
    assert!(
        body["diff"]["entries"].as_array().unwrap().is_empty(),
        "preview diff should be empty when the import has errors: {}",
        body["diff"]
    );
    assert_eq!(body["diff"]["summary"]["added"], 0);
}

/// Verify that zone import append rejects CNAME over existing db record.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_rejects_cname_over_existing_db_record() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Seed through the API so append must find a row absent from the file.
    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "type": "A", "value": "192.0.2.1" }
        ]),
    )
    .await;

    // Append a CNAME for the same owner in a different case: the scoped load must
    // match the existing A case-insensitively, so CNAME exclusivity rejects it.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "WWW IN CNAME target\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    // The original A is untouched and no CNAME was added.
    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["type"], "A");
    assert_eq!(items[0]["value"], "192.0.2.1");
}

/// Verify that zone import append rejects record over existing CNAME.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_rejects_record_over_existing_cname() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "alias", "type": "CNAME", "value": "target.example.com." }
        ]),
    )
    .await;

    // Append an A for the same owner: CNAME exclusivity must reject it.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "alias IN A 192.0.2.9\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=alias"),
            None,
        )
        .await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["type"], "CNAME");
}

/// Verify that zone import append dedups against existing db record.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_dedups_against_existing_db_record() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "type": "A", "value": "192.0.2.1" }
        ]),
    )
    .await;

    // Appending a record already present in the DB is a no-op, not a duplicate.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www IN A 192.0.2.1\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

/// Verify that zone import append into populated zone isolates names.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_append_into_populated_zone_isolates_names() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "a1", "type": "A", "value": "192.0.2.1" },
            { "name": "b1", "type": "A", "value": "192.0.2.2" }
        ]),
    )
    .await;

    // Appending a brand-new name adds only it; the existing names are untouched.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "c1 IN A 192.0.2.3\n", "mode": "append" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["unchanged"], 0);

    for name in ["a1", "b1", "c1"] {
        let (_, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&name={name}"),
                None,
            )
            .await;
        assert_eq!(
            body["items"].as_array().unwrap().len(),
            1,
            "expected exactly one record for {name}"
        );
    }
}
