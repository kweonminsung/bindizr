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
            "create",
            "zone",
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
            "create",
            "record",
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
        .run_cli_success(&["get", "records", "--zone", &zone_name, "--output", "json"])
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

    let deleted_record = app.run_cli_success(&["delete", "record", &record_id]).await;
    assert!(deleted_record.contains("deleted successfully"));

    let deleted_zone = app.run_cli_success(&["delete", "zone", &zone_name]).await;
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
            "create",
            "zone",
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
            "create",
            "record",
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
            "get", "records", "--zone", &one_zone, "--type", "A", "--output", "json",
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
        "create",
        "zone",
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
            "create",
            "record",
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
