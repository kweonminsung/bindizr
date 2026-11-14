mod export;
mod history;
mod import;
mod status;

use serde_json::Value;

use crate::common;
use crate::common::TestApp;

/// Verify that escaped trailing spaces are preserved through CLI/socket writes and escaped wildcard zones are rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn escaped_zone_names_follow_the_same_policy() {
    let app = TestApp::start_local().await;
    let base_zone_name = app.zone_name("cli-escaped");
    let simple_zone_name = format!("{base_zone_name}\\ ");
    let canonical_zone_name = format!(r"{base_zone_name}\032");

    let created = app
        .run_cli_success(
            &[
                "zone",
                "create",
                &simple_zone_name,
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
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");

    assert_eq!(created["zone"]["name"], canonical_zone_name);

    let fetched = app
        .run_cli_success(
            &["zone", "get", &canonical_zone_name, "--output", "json"],
            None,
        )
        .await;
    let fetched: Value = serde_json::from_str(&fetched).expect("CLI did not return valid JSON");

    assert_eq!(fetched["zone"]["name"], canonical_zone_name);

    let wildcard_zone_name = format!(r"\042.{base_zone_name}");
    let args = [
        "zone",
        "create",
        &wildcard_zone_name,
        "--mname",
        "ns.example",
        "--rname",
        "admin@example",
    ];

    let refused = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(&args, &refused, "wildcard");
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
    assert_eq!(zone["expire"], 1_209_600);
    assert_eq!(zone["minimum_ttl"], 120);
}

/// Verify that zones are created, retrieved, and deleted.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_supports_create_read_and_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-zone.example");
    let mname = format!("ns1.{zone_name}");

    let created = app.create_zone_cli(&zone_name, "3600").await;

    assert!(created.contains(&zone_name), "{created}");

    let fetched = app
        .run_cli_success(&["zone", "get", &zone_name, "--output", "json"], None)
        .await;
    let fetched: Value = serde_json::from_str(&fetched).expect("CLI did not return valid JSON");

    assert_eq!(fetched["zone"]["name"], zone_name);
    assert_eq!(fetched["zone"]["mname"], mname);

    let deleted = app
        .run_cli_success(&["zone", "delete", &zone_name], None)
        .await;

    assert!(deleted.contains("deleted successfully"));

    let args = ["zone", "get", &zone_name, "--output", "json"];

    let missing = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(
        &args,
        &missing,
        &format!("zone with name '{zone_name}' not found"),
    );
}

/// Verify that zone update changes only passed fields via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_update_changes_only_passed_fields() {
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

/// Verify that invalid zone names and TTLs are rejected.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_rejects_invalid_name_and_ttl() {
    let app = TestApp::start().await;

    for (zone_name, ttl, expected_error) in [
        ("bad..example", "3600", "empty labels"),
        ("low-ttl.example", "0", "ttl must be at least"),
    ] {
        let mname = format!("ns1.{zone_name}");
        let rname = format!("hostmaster@{zone_name}");
        let args = [
            "zone",
            "create",
            zone_name,
            "--mname",
            &mname,
            "--rname",
            &rname,
            "--default-ttl",
            ttl,
        ];

        let refused = app.run_cli(&args, None).await;
        common::assert_cli_failure_contains(&args, &refused, expected_error);
    }

    app.run_cli_success(&["status"], None).await;
}

/// Verify that zone listings filter and paginate.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_listing_filters_and_paginates() {
    let app = TestApp::start().await;
    let first_zone_name = app.zone_name("first.example");
    let filtered_zone_name = app.zone_name("filtered.example");

    for (zone_name, ttl) in [(&first_zone_name, "3600"), (&filtered_zone_name, "7200")] {
        app.create_zone_cli(zone_name, ttl).await;
    }

    let listed = app
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
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");
    let zones = listed["items"].as_array().expect("missing zone items");

    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone_name);

    let by_name = app
        .run_cli_success(
            &[
                "zone",
                "list",
                "--name",
                &first_zone_name,
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let by_name: Value = serde_json::from_str(&by_name).expect("CLI did not return valid JSON");
    let by_name = by_name["items"].as_array().expect("missing zone items");

    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0]["name"], first_zone_name);

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
async fn zone_create_omits_apex_ns_when_disabled() {
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

    let listed = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"], None)
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");

    assert_eq!(listed["pagination"]["total"], 0, "{listed}");
}
