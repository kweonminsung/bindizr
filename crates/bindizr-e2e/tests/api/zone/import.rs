use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::TestApp;

/// Populate a zone with records before testing an import.
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
        .send_request(
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
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    let before = body["items"].as_array().unwrap().len();

    // Real apply.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 3);

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), before + 3);

    // Re-applying in append mode is idempotent: everything is unchanged.
    let (status, body) = app
        .send_request(
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
            { "name": "keep", "type": "A", "value": "192.0.2.1" },
            { "name": "drop", "type": "A", "value": "192.0.2.2" }
        ]),
    )
    .await;

    // Replace: keep stays (same value), add is created, and both drop and the
    // apex NS go — the file is the desired state and lists neither.
    let content = "keep IN A 192.0.2.1\nadd IN A 192.0.2.3\n";
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "mode": "replace" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["deleted"], 2);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=drop"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let (_, body) = app
        .send_request(
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
            { "name": "www", "type": "A", "value": "192.0.2.1" },
            { "name": "www", "type": "A", "value": "192.0.2.2" },
            { "name": "www", "type": "TXT", "value": "keep me" },
            { "name": "other", "type": "A", "value": "192.0.2.9" }
        ]),
    )
    .await;

    // Only the `www` A RRset appears in the file, so only it is replaced.
    let content = "www IN A 192.0.2.3\n";
    let (status, body) = app
        .send_request(
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
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www&type=A"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["192.0.2.3"]);

    // Same owner, different type: untouched.
    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www&type=TXT"),
            None,
        )
        .await;
    assert_eq!(values(&body), vec!["keep me"]);

    // Different owner entirely: untouched.
    let (_, body) = app
        .send_request(
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
            { "name": "www", "type": "A", "value": "192.0.2.1", "ttl": 300 }
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
        .send_request(
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
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(ttl_of(&body), 600);

    // Re-importing the same TTL is idempotent: nothing to reconcile.
    let (_, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    // Append never modifies already-present records, TTL included.
    let (_, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www 900 IN A 192.0.2.1\n", "mode": "append" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .send_request(
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
    let app = TestApp::start_local().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www IN A 192.0.2.30\nmail 300 IN MX 10 mx.example.com.\n" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A transfer of the zone's own content replaces it with itself.
    let server = format!("127.0.0.1:{}", app.dns_port());
    let (status, body) = app
        .send_request(
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
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/import"),
                Some(request),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

/// Verify that `create` builds the zone from the file's SOA, and that a dry
/// run of the same import leaves no zone behind.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_creates_the_zone_from_the_files_soa() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-create.example");
    // A migrated zone's serial has to carry over, or a secondary holding the
    // old primary's higher serial ignores the transfer.
    let content = format!(
        "@ IN SOA ns1.old.example. hostmaster.{zone_name}. (2026091601 7200 1800 1209600 300)\n\
         @ IN NS ns1.old.example.\n\
         www IN A 192.0.2.10\n"
    );

    // A dry run plans against a zone it creates in the same transaction, and
    // discards both.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "create": true, "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    // The zone is created empty, so the file's NS and A are both adds.
    assert_eq!(body["summary"]["added"], 2);

    let (status, _) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "create": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true);

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let zone = &body["zone"];
    assert_eq!(zone["mname"], "ns1.old.example");
    assert_eq!(zone["rname"], format!("hostmaster@{zone_name}"));
    assert_eq!(zone["refresh"], 7200);
    assert_eq!(zone["retry"], 1800);
    assert_eq!(zone["expire"], 1209600);
    assert_eq!(zone["minimum_ttl"], 300);
    // The import advanced it once for the records it added.
    assert!(
        zone["serial"].as_i64().unwrap() >= 2026091601,
        "serial did not carry over: {}",
        zone["serial"]
    );
}

/// Verify that a missing zone is an error unless `create` says otherwise.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_refuses_a_missing_zone_without_create() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-nocreate.example");

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www IN A 192.0.2.10\n" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");

    // `create` needs an SOA to build the zone from.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "www IN A 192.0.2.10\n", "create": true })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("no SOA"), "{body}");
}

/// Verify that a rejected import leaves behind no zone it created to apply into.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_rejected_with_create_leaves_no_zone() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-create-reject.example");
    // The SOA is enough to create the zone from, but the CNAME collides with
    // the A record at the same name, so validation rejects the whole file.
    let content = format!(
        "@ IN SOA ns1.old.example. hostmaster.{zone_name}. (2026091601 7200 1800 1209600 300)\n\
         @ IN NS ns1.old.example.\n\
         www IN A 192.0.2.10\n\
         www IN CNAME target.example.\n"
    );

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content, "create": true })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["applied"], false);
    assert!(
        !body["errors"].as_array().expect("errors array").is_empty(),
        "{body}"
    );

    // The zone was created inside the transaction the rejection discarded.
    let (status, _) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

/// Verify that zone import accepts every user type and round-trips the export.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_accepts_every_user_type_and_round_trips_the_export() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The DS line precedes its delegation NS on purpose: exports sort DS
    // before NS at one owner, so import must not validate in file order.
    let content = concat!(
        "sub IN DS 12345 13 2 abababababababababababababababababababababababababababababababab\n",
        "sub IN NS ns1.example.net.\n",
        "@ IN CAA 0 issue \"letsencrypt.org\"\n",
        "ssh IN SSHFP 4 2 abababababababababababababababababababababababababababababababab\n",
        "_443._tcp IN TLSA 3 1 1 abababababababababababababababababababababababababababababababab\n",
    );

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["added"], 5);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0, "{body}");

    let (_, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=SSHFP"),
            None,
        )
        .await;
    assert_eq!(
        body["items"][0]["value"],
        format!(
            "4 2 {}",
            "abababababababababababababababababababababababababababababababab".to_uppercase()
        )
    );

    // The unsigned export must re-import as all-unchanged.
    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let exported = body.as_str().unwrap().to_string();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": exported })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["added"], 0, "{body}");
    assert_eq!(body["errors"].as_array().unwrap().len(), 0, "{body}");

    // The delegation NS cannot go while its DS survives; DS first, then NS.
    let record_id = |listing: &serde_json::Value| listing["items"][0]["id"].as_i64().unwrap();
    let (_, ns_listing) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=NS&name=sub"),
            None,
        )
        .await;
    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records/{}", record_id(&ns_listing)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (_, ds_listing) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=DS&name=sub"),
            None,
        )
        .await;
    for listing in [ds_listing, ns_listing] {
        let (status, _) = app
            .send_request(
                Method::DELETE,
                &format!("/records/{}", record_id(&listing)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
}

/// Verify that DNAME and NAPTR survive an import and export round trip.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dname_and_naptr_survive_an_import_and_export_round_trip() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = concat!(
        "tel IN NAPTR 200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .\n",
        "sip IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com.\n",
        "alias IN DNAME target.example.com.\n",
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true, "{body}");
    assert_eq!(body["summary"]["added"], 3, "{body}");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // The rdata comes back as written, the root replacement included.
    let exported = body.as_str().expect("zone file text");
    assert!(
        exported.contains("200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" ."),
        "{exported}"
    );
    assert!(
        exported.contains("100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.com."),
        "{exported}"
    );
    assert!(
        exported.contains("DNAME\ttarget.example.com."),
        "{exported}"
    );
}

/// Verify that escaped labels and values survive an import and export round trip.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn escaped_labels_and_values_survive_an_import_and_export_round_trip() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = concat!(
        "0/25 IN NS    ns.example.com.\n",
        "1    IN CNAME 1.0/25.2.0.192.in-addr.arpa.\n",
        "@    IN CAA   0 issue \"a\\\"b\\\\c\"\n",
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true, "{body}");
    assert_eq!(body["summary"]["added"], 3, "{body}");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // RFC 2317, Section 4 delegates through a label carrying a slash, and the
    // CAA value keeps the escapes it was written with.
    let exported = body.as_str().expect("zone file text");
    assert!(
        exported.contains("1.0/25.2.0.192.in-addr.arpa."),
        "{exported}"
    );
    assert!(exported.contains(r#"0 issue "a\"b\\c""#), "{exported}");
}
