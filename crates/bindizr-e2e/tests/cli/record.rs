use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

/// Verify record creation, retrieval, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_read_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli.example");

    let created_zone = app.create_zone_cli(&zone_name, "3600").await;
    assert!(created_zone.contains(&zone_name), "{created_zone}");

    let created_record = app
        .run_cli_success(&[
            "record",
            "create",
            &zone_name,
            "www",
            "--type",
            "A",
            "--value",
            "192.0.2.10",
            "--ttl",
            "300",
        ])
        .await;
    assert!(
        created_record.contains(&format!("www.{zone_name}."))
            && created_record.contains("192.0.2.10"),
        "{created_record}"
    );

    let records = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record = records
        .get("items")
        .and_then(Value::as_array)
        .and_then(|records| records.iter().find(|record| record["type"] == "A"))
        .expect("CLI did not return the created record");
    assert_eq!(record["name"], format!("www.{zone_name}."));
    assert_eq!(record["value"], "192.0.2.10");
    let record_id = record["id"]
        .as_i64()
        .expect("created record did not contain an ID")
        .to_string();

    let deleted_record = app
        .run_cli_success(&["record", "delete", "--id", &record_id])
        .await;
    assert!(deleted_record.contains("deleted successfully"));

    let deleted_zone = app.run_cli_success(&["zone", "delete", &zone_name]).await;
    assert!(deleted_zone.contains("deleted successfully"));
}

/// Verify that record bulk dry run shows the diff via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_dry_run_shows_the_diff_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("bulk-dry-run.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let records = r#"[
        {"name": "www", "type": "A", "value": "192.0.2.1"},
        {"name": "@", "type": "MX", "value": "mail.example.com", "priority": 10}
    ]"#;
    let dry_run = app
        .run_cli_success_with_input(
            &["record", "bulk-create", &zone_name, "-", "--dry-run"],
            records,
        )
        .await;
    assert!(dry_run.contains("+ www."), "{dry_run}");
    // The MX priority is re-inlined into the rdata for display.
    assert!(dry_run.contains("10 mail.example.com."), "{dry_run}");
    assert!(dry_run.contains("By name and type: +2 -0 ~0"), "{dry_run}");

    // Preview applies nothing.
    let listed = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["type"] != "MX"),
        "a dry run must not insert records"
    );
}

/// Verify that record update retype clears incompatible priority via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_retype_clears_incompatible_priority_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-retype.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "svc",
        "--type",
        "MX",
        "--value",
        "mail.example.com",
        "--priority",
        "10",
    ])
    .await;
    let records = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record_id = records["items"]
        .as_array()
        .and_then(|records| records.iter().find(|r| r["type"] == "MX"))
        .and_then(|r| r["id"].as_i64())
        .expect("created MX record did not contain an ID")
        .to_string();

    // Retyping to A must succeed even though --priority is not passed: the stale
    // MX priority is cleared rather than rejected.
    let updated = app
        .run_cli_success(&[
            "record",
            "update",
            "--id",
            &record_id,
            "--type",
            "A",
            "--value",
            "192.0.2.1",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    let updated = &updated["record"];
    assert_eq!(updated["type"], "A");
    assert_eq!(updated["value"], "192.0.2.1");
    assert!(
        updated["priority"].is_null(),
        "priority was: {}",
        updated["priority"]
    );
}

/// Verify that record update retype without value is rejected via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_retype_without_value_is_rejected_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-retype-noval.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.1",
    ])
    .await;
    let records = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record_id = records["items"]
        .as_array()
        .and_then(|records| records.iter().find(|r| r["type"] == "A"))
        .and_then(|r| r["id"].as_i64())
        .expect("created A record did not contain an ID")
        .to_string();

    // A record's stored value is encoded for its type, so a value carried over from
    // the old type is invalid for the new one — retyping must supply a fresh value.
    let args = ["record", "update", "--id", &record_id, "--type", "TXT"];
    let output = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &output, "value is required when changing");
}

/// Verify that record update changes only passed fields via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_changes_only_passed_fields_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-record-update.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.10",
        "--ttl",
        "300",
    ])
    .await;

    let records = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record_id = records["items"]
        .as_array()
        .and_then(|records| records.iter().find(|record| record["type"] == "A"))
        .and_then(|record| record["id"].as_i64())
        .expect("created record did not contain an ID")
        .to_string();

    let updated = app
        .run_cli_success(&[
            "record",
            "update",
            "--id",
            &record_id,
            "--value",
            "127.0.0.1",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    let updated = &updated["record"];
    assert_eq!(updated["value"], "127.0.0.1");
    assert_eq!(updated["ttl"], 300);
    assert_eq!(updated["type"], "A");
    assert_eq!(updated["name"], format!("www.{zone_name}."));
}

/// Verify record filtering by zone and type through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_filter_by_zone_and_type() {
    let app = TestApp::start().await;
    let one_zone = app.zone_name("one.example");
    let two_zone = app.zone_name("two.example");

    for zone in [&one_zone, &two_zone] {
        app.create_zone_cli(zone, "3600").await;
    }

    for (name, record_type, value, zone) in [
        ("www", "A", "192.0.2.1", one_zone.as_str()),
        ("alias", "CNAME", "www.one.example", one_zone.as_str()),
        ("www", "A", "192.0.2.2", two_zone.as_str()),
    ] {
        app.run_cli_success(&[
            "record",
            "create",
            zone,
            name,
            "--type",
            record_type,
            "--value",
            value,
            "--ttl",
            "300",
        ])
        .await;
    }

    let records = app
        .run_cli_success(&[
            "record", "list", &one_zone, "--type", "A", "--output", "json",
        ])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let records = records["items"].as_array().expect("missing record items");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("www.{one_zone}."));
    assert_eq!(records[0]["value"], "192.0.2.1");
}

/// Verify that invalid record values are rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_reject_invalid_values() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("validation.example");
    app.create_zone_cli(&zone_name, "3600").await;

    for (record_type, value, expected_error) in [
        ("A", "not-an-ip", "valid IPv4"),
        ("CNAME", "bad target.example", "must not contain whitespace"),
    ] {
        let args = [
            "record",
            "create",
            &zone_name,
            "invalid",
            "--type",
            record_type,
            "--value",
            value,
            "--ttl",
            "300",
        ];
        let output = app.run_cli(&args).await;
        assert_cli_failure_contains(&args, &output, expected_error);
    }
}

/// Verify bulk record insertion from standard input.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert_from_stdin() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("bulk.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let records = serde_json::json!([
        { "name": "www", "type": "A", "value": "192.0.2.20", "ttl": 300 },
        { "name": "mail", "type": "A", "value": "192.0.2.21", "ttl": 300 },
    ])
    .to_string();
    let dry_run = app
        .run_cli_success_with_input(
            &["record", "bulk-create", &zone_name, "-", "--dry-run"],
            &records,
        )
        .await;
    assert!(dry_run.contains("Dry run: 2 record(s) validated; nothing applied"));

    let listed = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    // A fresh zone holds only its auto-created NS record, so the absence of A
    // records proves the dry run persisted nothing.
    assert!(
        listed["items"]
            .as_array()
            .expect("missing record items")
            .iter()
            .all(|record| record["type"] != "A"),
        "dry run must not persist records"
    );

    let inserted = app
        .run_cli_success_with_input(&["record", "bulk-create", &zone_name, "-"], &records)
        .await;
    assert!(inserted.contains("Inserted 2 record(s)"));

    let yaml_records = "- name: ftp\n  type: A\n  value: 192.0.2.22\n  ttl: 300\n";
    let inserted_yaml = app
        .run_cli_success_with_input(&["record", "bulk-create", &zone_name, "-"], yaml_records)
        .await;
    assert!(inserted_yaml.contains("Inserted 1 record(s)"));

    let listed = app
        .run_cli_success(&[
            "record", "list", &zone_name, "--type", "A", "--output", "json",
        ])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    let names: Vec<String> = listed["items"]
        .as_array()
        .expect("missing record items")
        .iter()
        .map(|record| record["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&format!("www.{zone_name}.")));
    assert!(names.contains(&format!("mail.{zone_name}.")));
    assert!(names.contains(&format!("ftp.{zone_name}.")));
}

/// Verify creation of TXT segments from repeated CLI value options.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_txt_segments_from_repeated_value() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-txt.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let created = app
        .run_cli_success(&[
            "record", "create", &zone_name, "spf", "--type", "TXT", "--value", "v=spf1", "--value",
            "~all", "--output", "json",
        ])
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    assert_eq!(
        created["record"]["value"],
        serde_json::json!(["v=spf1", "~all"])
    );
    let record_id = created["record"]["id"].as_i64().unwrap().to_string();

    // A single --value is the plain value again.
    let updated = app
        .run_cli_success(&[
            "record",
            "update",
            "--id",
            &record_id,
            "--value",
            "v=spf1 ~all",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    assert_eq!(updated["record"]["value"], "v=spf1 ~all");
}

/// Verify that `record delete` takes a name instead of an ID, narrowing by type.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_by_name_narrows_by_type() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("delete-by-name.example");
    app.create_zone_cli(&zone_name, "3600").await;
    for (record_type, value) in [("A", "192.0.2.1"), ("TXT", "hello")] {
        app.run_cli_success(&[
            "record",
            "create",
            &zone_name,
            "www",
            "--type",
            record_type,
            "--value",
            value,
        ])
        .await;
    }

    // A dry run reports the count and leaves both records in place.
    let preview = app
        .run_cli_success(&["record", "delete", &zone_name, "www", "--dry-run"])
        .await;
    assert!(preview.contains("would be deleted"), "{preview}");

    // Narrowed to one type, so the TXT record stays.
    let deleted = app
        .run_cli_success(&["record", "delete", &zone_name, "www", "--type", "A"])
        .await;
    assert!(deleted.contains("1 record(s) deleted"), "{deleted}");

    let listed = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"])
        .await;
    let listed: serde_json::Value =
        serde_json::from_str(&listed).expect("record list did not print JSON");
    let types: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|record| record["type"].as_str().expect("type"))
        .collect();
    assert!(types.contains(&"TXT"), "{types:?}");
    assert!(!types.contains(&"A"), "{types:?}");
}

/// Verify that a TXT record is deleted by the value it was created with.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_delete_by_name_takes_a_txt_value_as_it_was_created() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("delete-txt-value.example");
    app.create_zone_cli(&zone_name, "3600").await;
    for value in ["hello world", "keep me"] {
        app.run_cli_success(&[
            "record", "create", &zone_name, "txt", "--type", "TXT", "--value", value,
        ])
        .await;
    }

    // The row holds the presentation form, so comparing the two spellings
    // byte for byte used to match nothing and report a successful no-op.
    let deleted = app
        .run_cli_success(&[
            "record",
            "delete",
            &zone_name,
            "txt",
            "--type",
            "TXT",
            "--value",
            "hello world",
        ])
        .await;
    assert!(deleted.contains("1 record(s) deleted"), "{deleted}");

    let listed = app
        .run_cli_success(&[
            "record", "list", &zone_name, "--type", "TXT", "--output", "json",
        ])
        .await;
    let listed: serde_json::Value =
        serde_json::from_str(&listed).expect("record list did not print JSON");
    let values: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|record| record["value"].as_str())
        .collect();
    assert_eq!(values, vec!["keep me"], "{listed}");
}

/// Verify that `record get` takes an owner name and lists every record there.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_get_by_name_lists_every_record_at_the_name() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("get-by-name.example");
    app.create_zone_cli(&zone_name, "3600").await;
    for (record_type, value) in [("A", "192.0.2.1"), ("TXT", "hello")] {
        app.run_cli_success(&[
            "record",
            "create",
            &zone_name,
            "www",
            "--type",
            record_type,
            "--value",
            value,
        ])
        .await;
    }

    // A name holds a record per type, so the name form answers with all of
    // them rather than failing the way a single-record lookup would.
    let listed = app
        .run_cli_success(&["record", "get", &zone_name, "www", "--output", "json"])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("record get did not print JSON");
    let mut types: Vec<&str> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|record| record["type"].as_str().expect("type"))
        .collect();
    types.sort_unstable();
    assert_eq!(types, vec!["A", "TXT"], "{listed}");
}

/// Verify that `record update` takes an owner name when the name holds one record.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_by_name_changes_the_one_record_at_the_name() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("update-by-name.example");
    app.create_zone_cli(&zone_name, "3600").await;
    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.1",
    ])
    .await;

    let updated = app
        .run_cli_success(&[
            "record",
            "update",
            &zone_name,
            "www",
            "--value",
            "192.0.2.2",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("record update did not print JSON");
    assert_eq!(updated["record"]["value"], "192.0.2.2", "{updated}");
}

/// Verify that `record update` refuses an owner name holding several records.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_by_name_refuses_a_name_holding_several_records() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("update-ambiguous.example");
    app.create_zone_cli(&zone_name, "3600").await;
    for (record_type, value) in [("A", "192.0.2.1"), ("TXT", "hello")] {
        app.run_cli_success(&[
            "record",
            "create",
            &zone_name,
            "www",
            "--type",
            record_type,
            "--value",
            value,
        ])
        .await;
    }

    // An update must address one record, so picking one of the two on the
    // caller's behalf would change a record they did not name.
    let args = [
        "record", "update", &zone_name, "www", "--ttl", "300", "--output", "json",
    ];
    let refused = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &refused, "address one by its id");
}
