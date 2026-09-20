use serde_json::Value;

use crate::common::TestApp;

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
