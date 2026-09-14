use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::{TestApp, TestAppOptions};

/// Populate a zone with records before testing an import.
async fn seed_records(app: &TestApp, zone_name: &str, records: Value) {
    let (status, _) = app
        .request(
            Method::POST,
            "/records/bulk",
            Some(json!({ "zone_name": zone_name, "records": records })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// Verify that zone-file import previews match the applied changes.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_dry_run_then_apply() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = "www IN A 192.0.2.10\nmail IN A 192.0.2.11\nftp IN CNAME www\n";

    // Dry run: reports the plan without applying it.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["summary"]["added"], 3);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0);

    // Nothing applied yet.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    let before = body["items"].as_array().unwrap().len();

    // Real apply.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 3);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), before + 3);

    // Re-applying in append mode is idempotent: everything is unchanged.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["unchanged"], 3);
}

/// Verify that replace imports reconcile all records in the zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_replace_mode() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "keep", "record_type": "A", "value": "192.0.2.1" },
            { "name": "drop", "record_type": "A", "value": "192.0.2.2" }
        ]),
    )
    .await;

    // Replace: keep stays (same value), drop is removed, add is created.
    let content = "keep IN A 192.0.2.1\nadd IN A 192.0.2.3\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "mode": "replace" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["deleted"], 1);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=drop"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=add"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

/// Verify that zone import zone file upsert mode replaces records by name and type only.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_upsert_mode_replaces_records_by_name_and_type_only() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The three ways upsert must differ from replace, which would drop all of
    // these: a multi-record RRset, another type on that owner, another owner.
    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "record_type": "A", "value": "192.0.2.1" },
            { "name": "www", "record_type": "A", "value": "192.0.2.2" },
            { "name": "www", "record_type": "TXT", "value": "keep me" },
            { "name": "other", "record_type": "A", "value": "192.0.2.9" }
        ]),
    )
    .await;

    // Only the `www` A RRset appears in the file, so only it is replaced.
    let content = "www IN A 192.0.2.3\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["deleted"], 2);

    let values = |body: &serde_json::Value| -> Vec<String> {
        let mut v: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["value"].as_str().unwrap().to_string())
            .collect();
        v.sort();
        v
    };

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www&record_type=A"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["192.0.2.3"]);

    // Same owner, different type: untouched.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www&record_type=TXT"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["keep me"]);

    // Different owner entirely: untouched.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=other"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["192.0.2.9"]);
}

/// Verify that zone import zone file reconciles TTL.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_reconciles_ttl() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    seed_records(
        &app,
        zone_name,
        json!([
            { "name": "www", "record_type": "A", "value": "192.0.2.1", "ttl": 300 }
        ]),
    )
    .await;

    let ttl_of = |body: &serde_json::Value| -> i64 {
        body["items"].as_array().unwrap()[0]["ttl"]
            .as_i64()
            .unwrap()
    };

    // A TTL-only upsert is reported as an update and must change the stored TTL.
    let content = "www 600 IN A 192.0.2.1\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["deleted"], 0);
    assert_eq!(body["summary"]["updated"], 1);
    assert_eq!(body["summary"]["unchanged"], 0);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(ttl_of(&body), 600);

    // Re-importing the same TTL is idempotent: nothing to reconcile.
    let (_, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    // Append never modifies already-present records, TTL included.
    let (_, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www 900 IN A 192.0.2.1\n", "mode": "append" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(ttl_of(&body), 600);
}

/// Verify importing a zone from another DNS server through the API.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_from_server_over_http() {
    // The transfer ACL must admit the test's own loopback AXFR.
    let app = TestApp::start_with_options(TestAppOptions {
        secondary_addrs: "127.0.0.1".to_string(),
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www IN A 192.0.2.30\nmail 300 IN MX 10 mx.example.com.\n" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A transfer of the zone's own content replaces it with itself.
    let server = format!("127.0.0.1:{}", app.dns_port());
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "from_server": server, "mode": "replace" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["parsed"], 3);
    assert_eq!(body["summary"]["unchanged"], 3);
    assert_eq!(body["summary"]["added"], 0);

    // Exactly one source, and that source one server.
    for request in [
        json!({}),
        json!({ "content": "www IN A 192.0.2.1\n", "from_server": server }),
        json!({ "from_server": "127.0.0.1:1,127.0.0.1:2", "mode": "replace" }),
    ] {
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/zones/{zone_name}/import"),
                Some(request),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
