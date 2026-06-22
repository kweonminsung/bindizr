use serde_json::Value;

use crate::common::{TestApp, assert_cli_success};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_read_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-zone.example");
    let primary_ns = format!("ns1.{zone_name}");

    let status = app.run_cli_success(&["status"]).await;
    assert!(status.contains("BINDIZR STATUS"));
    assert!(status.contains("Running"));

    let created = app
        .run_cli_success(&[
            "create",
            "zone",
            "--name",
            &zone_name,
            "--primary-ns",
            &primary_ns,
            "--admin-email",
            "hostmaster@cli-zone.example",
            "--ttl",
            "3600",
        ])
        .await;
    assert!(created.contains("Zone created successfully"));

    let zone = app
        .run_cli_success(&["get", "zones", &zone_name, "--output", "json"])
        .await;
    let zone: Value = serde_json::from_str(&zone).expect("CLI did not return valid JSON");
    assert_eq!(zone["name"], zone_name);
    assert_eq!(zone["primary_ns"], primary_ns);

    let deleted = app.run_cli_success(&["delete", "zone", &zone_name]).await;
    assert!(deleted.contains("deleted successfully"));

    let missing = app
        .run_cli(&["get", "zones", &zone_name, "--output", "json"])
        .await;
    let missing: Value =
        serde_json::from_slice(&missing.stdout).expect("missing zone response was not JSON");
    assert_eq!(missing, Value::Null);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_filter_and_paginate() {
    let app = TestApp::start().await;
    let first_zone = app.zone_name("first.example");
    let filtered_zone = app.zone_name("filtered.example");

    for (name, ttl) in [(&first_zone, "3600"), (&filtered_zone, "7200")] {
        app.run_cli_success(&[
            "create",
            "zone",
            "--name",
            name,
            "--primary-ns",
            &format!("ns1.{name}"),
            "--admin-email",
            &format!("hostmaster@{name}"),
            "--ttl",
            ttl,
        ])
        .await;
    }

    let zones = app
        .run_cli_success(&[
            "get",
            "zones",
            "--search",
            app.namespace(),
            "--min-ttl",
            "7000",
            "--max-ttl",
            "8000",
            "--output",
            "json",
        ])
        .await;
    let zones: Value = serde_json::from_str(&zones).expect("CLI did not return valid JSON");
    let zones = zones["items"].as_array().expect("missing zone items");
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone);

    let page = app
        .run_cli_success(&[
            "get",
            "zones",
            "--search",
            app.namespace(),
            "--limit",
            "1",
            "--offset",
            "1",
            "--output",
            "json",
        ])
        .await;
    let page: Value = serde_json::from_str(&page).expect("CLI did not return valid JSON");
    assert_eq!(
        page["items"].as_array().expect("missing zone items").len(),
        1
    );
    assert_eq!(page["pagination"]["total"], 2);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_reject_invalid_name_and_ttl() {
    let app = TestApp::start().await;

    for (name, ttl, expected_error) in [
        ("_tcp.example", "3600", "ASCII letters"),
        ("low-ttl.example", "0", "ttl must be at least"),
    ] {
        let output = app
            .run_cli(&[
                "create",
                "zone",
                "--name",
                name,
                "--primary-ns",
                &format!("ns1.{name}"),
                "--admin-email",
                &format!("hostmaster@{name}"),
                "--ttl",
                ttl,
            ])
            .await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(expected_error),
            "invalid zone response did not contain '{expected_error}': {stdout}"
        );
    }

    let status = app.run_cli(&["status"]).await;
    assert_cli_success(&["status"], &status);
}
