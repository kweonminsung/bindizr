use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn record_create_read_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli.example");
    let primary_ns = format!("ns1.{zone_name}");

    let created_zone = app
        .run_cli_success(&[
            "zone",
            "create",
            "--name",
            &zone_name,
            "--primary-ns",
            &primary_ns,
            "--admin-email",
            "hostmaster@cli.example",
            "--ttl",
            "3600",
        ])
        .await;
    assert!(created_zone.contains("Zone created successfully"));

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
    assert!(created_record.contains("Record created successfully"));

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
async fn record_filter_by_zone_and_type() {
    let app = TestApp::start().await;
    let one_zone = app.zone_name("one.example");
    let two_zone = app.zone_name("two.example");

    for zone in [&one_zone, &two_zone] {
        app.run_cli_success(&[
            "zone",
            "create",
            "--name",
            zone,
            "--primary-ns",
            &format!("ns1.{zone}"),
            "--admin-email",
            &format!("hostmaster@{zone}"),
            "--ttl",
            "3600",
        ])
        .await;
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
    let primary_ns = format!("ns1.{zone_name}");
    app.run_cli_success(&[
        "zone",
        "create",
        "--name",
        &zone_name,
        "--primary-ns",
        &primary_ns,
        "--admin-email",
        "hostmaster@validation.example",
        "--ttl",
        "3600",
    ])
    .await;

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
    let primary_ns = format!("ns1.{zone_name}");
    app.run_cli_success(&[
        "zone",
        "create",
        "--name",
        &zone_name,
        "--primary-ns",
        &primary_ns,
        "--admin-email",
        "hostmaster@bulk.example",
        "--ttl",
        "3600",
    ])
    .await;

    let records = serde_json::json!([
        { "name": "www", "record_type": "A", "value": "192.0.2.20", "ttl": 300 },
        { "name": "mail", "record_type": "A", "value": "192.0.2.21", "ttl": 300 },
    ])
    .to_string();
    let dry_run = app
        .run_cli_success_with_input(
            &["record", "bulk", "-", "--zone", &zone_name, "--dry-run"],
            &records,
        )
        .await;
    assert!(dry_run.contains("Dry run: 2 record(s) validated; nothing applied"));

    let listed = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    assert!(
        listed["items"]
            .as_array()
            .expect("missing record items")
            .iter()
            .all(|record| record["record_type"] != "A"),
        "dry run must not persist records"
    );

    let inserted = app
        .run_cli_success_with_input(&["record", "bulk", "-", "--zone", &zone_name], &records)
        .await;
    assert!(inserted.contains("Inserted 2 record(s)"));

    let yaml_records = "- name: ftp\n  record_type: A\n  value: 192.0.2.22\n  ttl: 300\n";
    let inserted_yaml = app
        .run_cli_success_with_input(&["record", "bulk", "-", "--zone", &zone_name], yaml_records)
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
