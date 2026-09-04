use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

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
            "--name",
            "www",
            "--type",
            "A",
            "--value",
            "192.0.2.10",
            "--zone",
            &zone_name,
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
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record = records
        .get("items")
        .and_then(Value::as_array)
        .and_then(|records| records.iter().find(|record| record["record_type"] == "A"))
        .expect("CLI did not return the created record");
    assert_eq!(record["name"], format!("www.{zone_name}."));
    assert_eq!(record["value"], "192.0.2.10");
    let record_id = record["id"]
        .as_i64()
        .expect("created record did not contain an ID")
        .to_string();

    let deleted_record = app.run_cli_success(&["record", "delete", &record_id]).await;
    assert!(deleted_record.contains("deleted successfully"));

    let deleted_zone = app.run_cli_success(&["zone", "delete", &zone_name]).await;
    assert!(deleted_zone.contains("deleted successfully"));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_preview_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("bulk-preview.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let records = r#"[
        {"name": "www", "record_type": "A", "value": "192.0.2.1"},
        {"name": "@", "record_type": "MX", "value": "mail.example.com", "priority": 10}
    ]"#;
    let preview = app
        .run_cli_success_with_input(
            &[
                "record",
                "bulk-create",
                "-",
                "--zone",
                &zone_name,
                "--preview",
            ],
            records,
        )
        .await;
    assert!(preview.contains("+ www."), "preview was: {preview}");
    // The MX priority is re-inlined into the rdata for display.
    assert!(
        preview.contains("10 mail.example.com."),
        "preview was: {preview}"
    );
    assert!(
        preview.contains("Records: +2 -0 ~0"),
        "preview was: {preview}"
    );

    // Preview applies nothing.
    let listed = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    assert!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["record_type"] != "MX"),
        "preview should not have inserted records"
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_retype_clears_incompatible_priority_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-retype.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&[
        "record",
        "create",
        "--name",
        "svc",
        "--type",
        "MX",
        "--value",
        "mail.example.com",
        "--priority",
        "10",
        "--zone",
        &zone_name,
    ])
    .await;
    let records = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record_id = records["items"]
        .as_array()
        .and_then(|records| records.iter().find(|r| r["record_type"] == "MX"))
        .and_then(|r| r["id"].as_i64())
        .expect("created MX record did not contain an ID")
        .to_string();

    // Retyping to A must succeed even though --priority is not passed: the stale
    // MX priority is cleared rather than rejected.
    let updated = app
        .run_cli_success(&[
            "record",
            "update",
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
    assert_eq!(updated["record_type"], "A");
    assert_eq!(updated["value"], "192.0.2.1");
    assert!(
        updated["priority"].is_null(),
        "priority was: {}",
        updated["priority"]
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_retype_without_value_is_rejected_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-retype-noval.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&[
        "record",
        "create",
        "--name",
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.1",
        "--zone",
        &zone_name,
    ])
    .await;
    let records = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record_id = records["items"]
        .as_array()
        .and_then(|records| records.iter().find(|r| r["record_type"] == "A"))
        .and_then(|r| r["id"].as_i64())
        .expect("created A record did not contain an ID")
        .to_string();

    // A record's stored value is encoded for its type, so a value carried over from
    // the old type is invalid for the new one — retyping must supply a fresh value.
    let args = ["record", "update", &record_id, "--type", "TXT"];
    let output = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &output, "value is required when changing");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_update_changes_only_passed_fields_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-record-update.example");
    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&[
        "record",
        "create",
        "--name",
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.10",
        "--zone",
        &zone_name,
        "--ttl",
        "300",
    ])
    .await;

    let records = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let record_id = records["items"]
        .as_array()
        .and_then(|records| records.iter().find(|record| record["record_type"] == "A"))
        .and_then(|record| record["id"].as_i64())
        .expect("created record did not contain an ID")
        .to_string();

    let updated = app
        .run_cli_success(&[
            "record",
            "update",
            &record_id,
            "--value",
            "127.0.0.1",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    assert_eq!(updated["value"], "127.0.0.1");
    assert_eq!(updated["ttl"], 300);
    assert_eq!(updated["record_type"], "A");
    assert_eq!(updated["name"], format!("www.{zone_name}."));
}

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
            "--name",
            name,
            "--type",
            record_type,
            "--value",
            value,
            "--zone",
            zone,
            "--ttl",
            "300",
        ])
        .await;
    }

    let records = app
        .run_cli_success(&[
            "record", "list", "--zone", &one_zone, "--type", "A", "--output", "json",
        ])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let records = records["items"].as_array().expect("missing record items");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], format!("www.{one_zone}."));
    assert_eq!(records[0]["value"], "192.0.2.1");
}

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
            "--name",
            "invalid",
            "--type",
            record_type,
            "--value",
            value,
            "--zone",
            &zone_name,
            "--ttl",
            "300",
        ];
        let output = app.run_cli(&args).await;
        assert_cli_failure_contains(&args, &output, expected_error);
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_bulk_insert_from_stdin() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("bulk.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let records = serde_json::json!([
        { "name": "www", "record_type": "A", "value": "192.0.2.20", "ttl": 300 },
        { "name": "mail", "record_type": "A", "value": "192.0.2.21", "ttl": 300 },
    ])
    .to_string();
    let dry_run = app
        .run_cli_success_with_input(
            &[
                "record",
                "bulk-create",
                "-",
                "--zone",
                &zone_name,
                "--dry-run",
            ],
            &records,
        )
        .await;
    assert!(dry_run.contains("Dry run: 2 record(s) validated; nothing applied"));

    let listed = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    // A fresh zone holds only its auto-created NS record, so the absence of A
    // records proves the dry run persisted nothing.
    assert!(
        listed["items"]
            .as_array()
            .expect("missing record items")
            .iter()
            .all(|record| record["record_type"] != "A"),
        "dry run must not persist records"
    );

    let inserted = app
        .run_cli_success_with_input(
            &["record", "bulk-create", "-", "--zone", &zone_name],
            &records,
        )
        .await;
    assert!(inserted.contains("Inserted 2 record(s)"));

    let yaml_records = "- name: ftp\n  record_type: A\n  value: 192.0.2.22\n  ttl: 300\n";
    let inserted_yaml = app
        .run_cli_success_with_input(
            &["record", "bulk-create", "-", "--zone", &zone_name],
            yaml_records,
        )
        .await;
    assert!(inserted_yaml.contains("Inserted 1 record(s)"));

    let listed = app
        .run_cli_success(&[
            "record", "list", "--zone", &zone_name, "--type", "A", "--output", "json",
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
