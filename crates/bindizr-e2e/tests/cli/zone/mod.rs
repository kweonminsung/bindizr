use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains, assert_cli_success};

mod export;
mod history;
mod import;
mod status;

/// Preserve escaped trailing spaces through CLI/socket writes and reject escaped wildcard zones.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn escaped_zone_names_follow_the_same_policy_via_cli() {
    let app = TestApp::start_local().await;
    let base = app.zone_name("cli-escaped");
    let simple = format!("{base}\\ ");
    let canonical = format!(r"{base}\032");

    let created = app
        .run_cli_success(
            &[
                "zone",
                "create",
                &simple,
                "--mname",
                "ns.example",
                "--rname",
                "admin@example",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let created: Value = serde_json::from_str(&created).unwrap();

    assert_eq!(created["zone"]["name"], canonical);

    let read = app
        .run_cli_success(&["zone", "get", &canonical, "--output", "json"], None)
        .await;
    let read: Value = serde_json::from_str(&read).unwrap();

    assert_eq!(read["zone"]["name"], canonical);
    let wildcard = format!(r"\042.{base}");
    let args = [
        "zone",
        "create",
        &wildcard,
        "--mname",
        "ns.example",
        "--rname",
        "admin@example",
    ];

    let output = app.run_cli(&args, None).await;
    assert_cli_failure_contains(&args, &output, "wildcard");
}

/// Verify that zone create takes SOA timers.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_takes_soa_timers() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-soa.example");
    let mname = format!("ns1.{zone_name}");
    let rname = format!("hostmaster@{zone_name}");

    let created = app
        .run_cli_success(
            &[
                "zone",
                "create",
                &zone_name,
                "--mname",
                &mname,
                "--rname",
                &rname,
                "--default-ttl",
                "3600",
                "--refresh",
                "300",
                "--retry",
                "60",
                "--expire",
                "1209600",
                "--minimum-ttl",
                "120",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    let zone = &created["zone"];

    assert_eq!(zone["refresh"], 300);
    assert_eq!(zone["retry"], 60);
    assert_eq!(zone["expire"], 1209600);
    assert_eq!(zone["minimum_ttl"], 120);
}

/// Verify zone creation, retrieval, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_supports_create_read_and_delete_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-zone.example");
    let mname = format!("ns1.{zone_name}");

    let created = app.create_zone_cli(&zone_name, "3600").await;

    assert!(created.contains(&zone_name), "{created}");

    let zone = app
        .run_cli_success(&["zone", "get", &zone_name, "--output", "json"], None)
        .await;
    let zone: Value = serde_json::from_str(&zone).expect("CLI did not return valid JSON");

    assert_eq!(zone["zone"]["name"], zone_name);
    assert_eq!(zone["zone"]["mname"], mname);

    let deleted = app
        .run_cli_success(&["zone", "delete", &zone_name], None)
        .await;

    assert!(deleted.contains("deleted successfully"));

    let args = ["zone", "get", &zone_name, "--output", "json"];

    let missing = app.run_cli(&args, None).await;
    assert_cli_failure_contains(
        &args,
        &missing,
        &format!("zone with name '{zone_name}' not found"),
    );
}

/// Verify that zone update changes only passed fields via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_update_changes_only_passed_fields_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-update.example");

    app.create_zone_cli(&zone_name, "3600").await;

    let updated = app
        .run_cli_success(
            &[
                "zone",
                "update",
                &zone_name,
                "--refresh",
                "300",
                "--retry",
                "60",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    let updated = &updated["zone"];

    assert_eq!(updated["refresh"], 300);
    assert_eq!(updated["retry"], 60);
    assert_eq!(updated["default_ttl"], 3600);
    assert_eq!(updated["mname"], format!("ns1.{zone_name}"));
}

/// Verify rejection of invalid zone names and TTLs.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rejects_invalid_name_and_ttl_via_cli() {
    let app = TestApp::start().await;

    for (name, ttl, expected_error) in [
        ("bad..example", "3600", "empty labels"),
        ("low-ttl.example", "0", "ttl must be at least"),
    ] {
        let mname = format!("ns1.{name}");
        let rname = format!("hostmaster@{name}");
        let args = [
            "zone",
            "create",
            name,
            "--mname",
            &mname,
            "--rname",
            &rname,
            "--default-ttl",
            ttl,
        ];

        let output = app.run_cli(&args, None).await;
        assert_cli_failure_contains(&args, &output, expected_error);
    }

    let status = app.run_cli(&["status"], None).await;
    assert_cli_success(&["status"], &status);
}

/// Verify zone filtering and pagination.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_listing_filters_and_paginates_via_cli() {
    let app = TestApp::start().await;
    let first_zone = app.zone_name("first.example");
    let filtered_zone = app.zone_name("filtered.example");

    for (name, ttl) in [(&first_zone, "3600"), (&filtered_zone, "7200")] {
        app.create_zone_cli(name, ttl).await;
    }

    let zones = app
        .run_cli_success(
            &[
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
            ],
            None,
        )
        .await;
    let zones: Value = serde_json::from_str(&zones).expect("CLI did not return valid JSON");
    let zones = zones["items"].as_array().expect("missing zone items");

    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone);

    let by_name = app
        .run_cli_success(
            &["zone", "list", "--name", &first_zone, "--output", "json"],
            None,
        )
        .await;
    let by_name: Value = serde_json::from_str(&by_name).expect("CLI did not return valid JSON");
    let by_name = by_name["items"].as_array().expect("missing zone items");

    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0]["name"], first_zone);

    let page = app
        .run_cli_success(
            &[
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
            ],
            None,
        )
        .await;
    let page: Value = serde_json::from_str(&page).expect("CLI did not return valid JSON");

    assert_eq!(
        page["items"].as_array().expect("missing zone items").len(),
        1
    );
    assert_eq!(page["pagination"]["total"], 2);
}

/// Verify that `--no-apex-ns` creates a zone with no records.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_omits_apex_ns_when_disabled_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("bare-cli.example.com");
    let mname = format!("ns1.{zone_name}");

    app.run_cli_success(
        &[
            "zone",
            "create",
            &zone_name,
            "--mname",
            &mname,
            "--rname",
            "admin@example.com",
            "--no-apex-ns",
        ],
        None,
    )
    .await;

    let records = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"], None)
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");

    assert_eq!(records["pagination"]["total"], 0, "{records}");
}
