use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains, assert_cli_success};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_read_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-zone.example");
    let primary_ns = format!("ns1.{zone_name}");

    let status = app.run_cli_success(&["status"]).await;
    assert!(status.contains("BINDIZR STATUS"));
    assert!(status.contains("Running"));

    let created = app.create_zone_cli(&zone_name, "3600").await;
    assert!(created.contains("Zone created successfully"));

    let zone = app
        .run_cli_success(&["zone", "get", &zone_name, "--output", "json"])
        .await;
    let zone: Value = serde_json::from_str(&zone).expect("CLI did not return valid JSON");
    assert_eq!(zone["name"], zone_name);
    assert_eq!(zone["primary_ns"], primary_ns);

    let deleted = app.run_cli_success(&["zone", "delete", &zone_name]).await;
    assert!(deleted.contains("deleted successfully"));

    let args = ["zone", "get", &zone_name, "--output", "json"];
    let missing = app.run_cli(&args).await;
    assert_cli_failure_contains(
        &args,
        &missing,
        &format!("Zone with name '{zone_name}' not found"),
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_filter_and_paginate() {
    let app = TestApp::start().await;
    let first_zone = app.zone_name("first.example");
    let filtered_zone = app.zone_name("filtered.example");

    for (name, ttl) in [(&first_zone, "3600"), (&filtered_zone, "7200")] {
        app.create_zone_cli(name, ttl).await;
    }

    let zones = app
        .run_cli_success(&[
            "zone",
            "list",
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

    let by_name = app
        .run_cli_success(&["zone", "list", "--name", &first_zone, "--output", "json"])
        .await;
    let by_name: Value = serde_json::from_str(&by_name).expect("CLI did not return valid JSON");
    let by_name = by_name["items"].as_array().expect("missing zone items");
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0]["name"], first_zone);

    let page = app
        .run_cli_success(&[
            "zone",
            "list",
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
        let primary_ns = format!("ns1.{name}");
        let admin_email = format!("hostmaster@{name}");
        let args = [
            "zone",
            "create",
            "--name",
            name,
            "--primary-ns",
            &primary_ns,
            "--admin-email",
            &admin_email,
            "--ttl",
            ttl,
        ];
        let output = app.run_cli(&args).await;
        assert_cli_failure_contains(&args, &output, expected_error);
    }

    let status = app.run_cli(&["status"]).await;
    assert_cli_success(&["status"], &status);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_from_stdin() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let imported = app
        .run_cli_success_with_input(
            &["zone", "import", &zone_name, "-", "--output", "json"],
            "www IN A 192.0.2.30\nmail IN A 192.0.2.31\n",
        )
        .await;
    let imported: Value = serde_json::from_str(&imported).expect("CLI did not return valid JSON");
    assert_eq!(imported["applied"], true);
    assert_eq!(imported["summary"]["added"], 2);

    let dry_run = app
        .run_cli_success_with_input(
            &[
                "zone",
                "import",
                &zone_name,
                "-",
                "--dry-run",
                "--output",
                "json",
            ],
            "extra IN A 192.0.2.32\n",
        )
        .await;
    let dry_run: Value = serde_json::from_str(&dry_run).expect("CLI did not return valid JSON");
    assert_eq!(dry_run["applied"], false);
    assert_eq!(dry_run["dry_run"], true);

    let records = app
        .run_cli_success(&[
            "record", "list", "--zone", &zone_name, "--type", "A", "--output", "json",
        ])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    assert_eq!(
        records["items"]
            .as_array()
            .expect("missing record items")
            .len(),
        2
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_snapshots_and_rollback_flow() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("history.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let zone = app
        .run_cli_success(&["zone", "get", &zone_name, "--output", "json"])
        .await;
    let zone: Value = serde_json::from_str(&zone).expect("CLI did not return valid JSON");
    assert_eq!(zone["serial"].as_i64().unwrap(), 1);

    app.run_cli_success(&[
        "record",
        "create",
        "--name",
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.80",
        "--zone",
        &zone_name,
    ])
    .await;
    let target_serial = "2"; // zone create = 1, record create = 2
    app.run_cli_success(&[
        "record",
        "create",
        "--name",
        "extra",
        "--type",
        "A",
        "--value",
        "192.0.2.81",
        "--zone",
        &zone_name,
    ])
    .await;

    let snapshots = app
        .run_cli_success(&["zone", "snapshot", "list", &zone_name, "--output", "json"])
        .await;
    let snapshots: Value = serde_json::from_str(&snapshots).expect("CLI did not return valid JSON");
    let serials: Vec<i64> = snapshots["items"]
        .as_array()
        .expect("missing snapshot items")
        .iter()
        .map(|item| item["serial"].as_i64().unwrap())
        .collect();
    assert_eq!(serials, [3, 2, 1]);

    let detail = app
        .run_cli_success(&[
            "zone",
            "snapshot",
            "get",
            &zone_name,
            target_serial,
            "--output",
            "json",
        ])
        .await;
    let detail: Value = serde_json::from_str(&detail).expect("CLI did not return valid JSON");
    let a_records: Vec<&str> = detail["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["record_type"] == "A")
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(a_records, ["www"]);

    let dry_run = app
        .run_cli_success(&["zone", "rollback", &zone_name, target_serial, "--dry-run"])
        .await;
    assert!(dry_run.contains("Dry run"));
    assert!(dry_run.contains("nothing applied"));

    let rolled_back = app
        .run_cli_success(&["zone", "rollback", &zone_name, target_serial])
        .await;
    assert!(rolled_back.contains("Zone rolled back to serial 2 (new serial 4)"));

    let records = app
        .run_cli_success(&[
            "record", "list", "--zone", &zone_name, "--type", "A", "--output", "json",
        ])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    let names: Vec<&str> = records["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].starts_with("www."));

    // Rolling back to the current serial is rejected with a hint.
    let args = ["zone", "rollback", &zone_name, "4"];
    let output = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &output, "must be less than the current serial");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_status_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("status.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let status = app.run_cli_success(&["zone", "status", &zone_name]).await;
    assert!(status.contains(&format!("Zone {} (serial 1)", zone_name)));

    let json_output = app
        .run_cli_success(&["zone", "status", &zone_name, "--output", "json"])
        .await;
    let parsed: Value = serde_json::from_str(&json_output).expect("CLI did not return valid JSON");
    assert_eq!(parsed["zone"], zone_name);
    assert_eq!(parsed["serial"].as_i64().unwrap(), 1);
    if !app.has_dns_secondaries() {
        assert!(status.contains("No secondaries configured."));
        assert!(parsed["secondaries"].as_array().unwrap().is_empty());
    }
}
