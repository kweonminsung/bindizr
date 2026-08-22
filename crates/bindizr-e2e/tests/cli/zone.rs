use serde_json::{Value, json};

use crate::common::{TestApp, assert_cli_failure_contains, assert_cli_success};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_read_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-zone.example");
    let mname = format!("ns1.{zone_name}");

    let created = app.create_zone_cli(&zone_name, "3600").await;
    assert!(created.contains("Zone created successfully"));

    let zone = app
        .run_cli_success(&["zone", "get", &zone_name, "--output", "json"])
        .await;
    let zone: Value = serde_json::from_str(&zone).expect("CLI did not return valid JSON");
    assert_eq!(zone["name"], zone_name);
    assert_eq!(zone["mname"], mname);

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
async fn zone_update_changes_only_passed_fields_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-update.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let updated = app
        .run_cli_success(&[
            "zone",
            "update",
            &zone_name,
            "--refresh",
            "300",
            "--retry",
            "60",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    assert_eq!(updated["refresh"], 300);
    assert_eq!(updated["retry"], 60);
    // Omitted fields keep their current values.
    assert_eq!(updated["default_ttl"], 3600);
    assert_eq!(updated["mname"], format!("ns1.{zone_name}"));
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
            "--min-default-ttl",
            "7000",
            "--max-default-ttl",
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
        let mname = format!("ns1.{name}");
        let rname = format!("hostmaster@{name}");
        let args = [
            "zone",
            "create",
            "--name",
            name,
            "--mname",
            &mname,
            "--rname",
            &rname,
            "--default-ttl",
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
async fn zone_export_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("export.example");
    // Zone TTL is deliberately not 3600 so an inherited TTL is distinguishable.
    app.create_zone_cli(&zone_name, "7200").await;
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
        "--ttl",
        "300",
    ])
    .await;

    // An omitted TTL is fixed to the zone's TTL (7200) at write time.
    app.run_cli_success(&[
        "record",
        "create",
        "--name",
        "nottl",
        "--type",
        "A",
        "--value",
        "192.0.2.2",
        "--zone",
        &zone_name,
    ])
    .await;

    let exported = app.run_cli_success(&["zone", "export", &zone_name]).await;
    assert!(
        exported.contains(&format!("$ORIGIN {zone_name}.")),
        "{exported}"
    );
    assert!(exported.contains("$TTL 7200"), "{exported}");
    assert!(exported.contains("IN\tSOA\t"), "{exported}");
    assert!(
        exported.contains("www\t300\tIN\tA\t192.0.2.1"),
        "{exported}"
    );
    assert!(
        exported.contains("nottl\t7200\tIN\tA\t192.0.2.2"),
        "{exported}"
    );

    // Re-importing the export into the same zone changes nothing.
    let reimport = app
        .run_cli_success_with_input(
            &["zone", "import", &zone_name, "-", "--output", "json"],
            &exported,
        )
        .await;
    let reimport: Value = serde_json::from_str(&reimport).expect("CLI did not return valid JSON");
    assert_eq!(reimport["summary"]["added"], 0, "{reimport}");
    assert_eq!(reimport["summary"]["deleted"], 0, "{reimport}");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_export_orders_by_name_then_type_then_rdata() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("export-order.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // Fed in deliberately unsorted; rows also come back from the DB in no
    // guaranteed order, so the export's own sort is what the assertion pins.
    app.run_cli_success_with_input(
        &["zone", "import", &zone_name, "-"],
        "b IN A 192.0.2.2\n\
         a IN TXT \"zzz\"\n\
         a IN A 192.0.2.10\n\
         a IN A 192.0.2.2\n\
         a IN MX 10 mail.example.com.\n",
    )
    .await;

    let exported = app.run_cli_success(&["zone", "export", &zone_name]).await;
    let ordered: Vec<&str> = exported
        .lines()
        .filter(|l| l.starts_with("a\t") || l.starts_with("b\t"))
        .collect();

    // Rdata ties break as text, so 192.0.2.10 sorts before 192.0.2.2.
    assert_eq!(
        ordered,
        vec![
            "a\t3600\tIN\tA\t192.0.2.10",
            "a\t3600\tIN\tA\t192.0.2.2",
            "a\t3600\tIN\tMX\t10 mail.example.com.",
            "a\t3600\tIN\tTXT\t\"zzz\"",
            "b\t3600\tIN\tA\t192.0.2.2",
        ],
        "{exported}"
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_preview_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-preview.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // Preview renders a +/-/~ diff and, being a dry run, applies nothing.
    let preview = app
        .run_cli_success_with_input(
            &["zone", "import", &zone_name, "-", "--preview"],
            "www IN A 192.0.2.30\nmail IN A 192.0.2.31\n",
        )
        .await;
    assert!(preview.contains("+ www."), "preview was: {preview}");
    assert!(
        preview.contains("Records: +2 -0 ~0"),
        "preview was: {preview}"
    );

    let records = app
        .run_cli_success(&["record", "list", "--zone", &zone_name, "--output", "json"])
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    // Only the apex NS seeded at creation exists; the preview applied nothing.
    let names: Vec<&str> = records["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["record_type"] == "A")
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(names.is_empty(), "records were: {names:?}");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_versions_and_rollback_flow() {
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

    let versions = app
        .run_cli_success(&["zone", "version", "list", &zone_name, "--output", "json"])
        .await;
    let versions: Value = serde_json::from_str(&versions).expect("CLI did not return valid JSON");
    let serials: Vec<i64> = versions["items"]
        .as_array()
        .expect("missing version items")
        .iter()
        .map(|item| item["serial"].as_i64().unwrap())
        .collect();
    assert_eq!(serials, [3, 2, 1]);

    let detail = app
        .run_cli_success(&[
            "zone",
            "version",
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

    // Serial 1 -> 2 added the www A record; 2 -> 3 added extra.
    let diff = app
        .run_cli_success(&[
            "zone", "version", "diff", &zone_name, "1", "2", "--output", "json",
        ])
        .await;
    let diff: Value = serde_json::from_str(&diff).expect("CLI did not return valid JSON");
    assert_eq!(
        diff["diff"]["summary"],
        json!({ "added": 1, "removed": 0, "changed": 0 })
    );
    let added = &diff["diff"]["entries"][0];
    assert_eq!(added["change"], "added");
    assert_eq!(added["name"], format!("www.{zone_name}."));
    // The value is structured (display form), not a rendered rdata string.
    assert_eq!(added["to"][0]["value"], "192.0.2.80");

    // Omitting the second serial compares against the current serial (3).
    let diff_to_current = app
        .run_cli_success(&[
            "zone", "version", "diff", &zone_name, "1", "--output", "json",
        ])
        .await;
    let diff_to_current: Value =
        serde_json::from_str(&diff_to_current).expect("CLI did not return valid JSON");
    assert_eq!(diff_to_current["to_serial"].as_i64().unwrap(), 3);
    assert_eq!(
        diff_to_current["diff"]["summary"]["added"]
            .as_i64()
            .unwrap(),
        2
    );

    let dry_run = app
        .run_cli_success(&[
            "zone",
            "version",
            "rollback",
            &zone_name,
            target_serial,
            "--dry-run",
        ])
        .await;
    assert!(dry_run.contains("Dry run"));
    assert!(dry_run.contains("nothing applied"));

    let rolled_back = app
        .run_cli_success(&["zone", "version", "rollback", &zone_name, target_serial])
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
    let args = ["zone", "version", "rollback", &zone_name, "4"];
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
