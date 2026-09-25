use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

/// Verify zone history inspection and rollback through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_versions_and_rollback_flow() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("history.example");

    // Build three versions so rollback can preserve www while removing the later
    // extra. The zone is created directly so the serials count from its own
    // first mutation.
    app.run_cli_success(&[
        "zone",
        "create",
        &zone_name,
        "--mname",
        &format!("ns1.{zone_name}"),
        "--rname",
        &format!("hostmaster@{zone_name}"),
        "--default-ttl",
        "3600",
    ])
    .await;

    let zone = app
        .run_cli_success(&["zone", "get", &zone_name, "--output", "json"])
        .await;
    let zone: Value = serde_json::from_str(&zone).expect("CLI did not return valid JSON");
    assert_eq!(zone["zone"]["serial"].as_i64().unwrap(), 1);

    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "www",
        "--type",
        "A",
        "--value",
        "192.0.2.80",
    ])
    .await;
    let target_serial = "2"; // zone create = 1, record create = 2
    app.run_cli_success(&[
        "record",
        "create",
        &zone_name,
        "extra",
        "--type",
        "A",
        "--value",
        "192.0.2.81",
    ])
    .await;

    // Inspect the version list and the target snapshot before comparing changes.
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
        .filter(|record| record["type"] == "A")
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(a_records, [format!("www.{zone_name}.")]);

    // Serial 1 -> 2 added the www A record; 2 -> 3 added extra.
    let diff = app
        .run_cli_success(&["zone", "version", "diff", &zone_name, "1", "2"])
        .await;
    assert!(diff.contains("SOA serial: 1 -> 2"), "{diff}");
    assert!(diff.contains("By name and type: +1 -0 ~0"), "{diff}");
    // The added RRset renders as a zone-file line under a `+`.
    assert!(diff.contains(&format!("+ www.{zone_name}.")), "{diff}");
    assert!(
        diff.contains("IN A") && diff.contains("192.0.2.80"),
        "{diff}"
    );

    // Omitting the second serial compares against the current serial (3).
    let diff_to_current = app
        .run_cli_success(&["zone", "version", "diff", &zone_name, "1"])
        .await;
    assert!(
        diff_to_current.contains("SOA serial: 1 -> 3"),
        "{diff_to_current}"
    );
    assert!(
        diff_to_current.contains("By name and type: +2 -0 ~0"),
        "{diff_to_current}"
    );

    // Preview the rollback without advancing the current serial or changing records.
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

    // Apply the same target as a new serial and verify only its records remain.
    let rolled_back = app
        .run_cli_success(&["zone", "version", "rollback", &zone_name, target_serial])
        .await;
    assert!(rolled_back.contains("Zone rolled back to serial 2 (new serial 4)"));

    let records = app
        .run_cli_success(&[
            "record", "list", &zone_name, "--type", "A", "--output", "json",
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
