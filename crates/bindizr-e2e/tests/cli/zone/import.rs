use serde_json::Value;

use crate::{
    cli::common::{summary_cells, summary_row},
    common::TestApp,
};

/// Preserve a high source serial during preview and advance it when applying records.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_accepts_the_full_serial_range() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-high-serial.example");
    let content = format!(
        "@ IN SOA ns.old.example. hostmaster.{zone_name}. (4294967295 7200 1800 1209600 300)\n@ IN NS ns.old.example.\nwww IN A 192.0.2.10\n"
    );
    app.run_cli_success(
        &["zone", "import", &zone_name, "-", "--create", "--dry-run"],
        Some(&content),
    )
    .await;
    assert!(
        !app.run_cli(&["zone", "get", &zone_name], None)
            .await
            .status
            .success()
    );
    app.run_cli_success(
        &["zone", "import", &zone_name, "-", "--create"],
        Some(&content),
    )
    .await;
    assert_eq!(app.read_zone_serial(&zone_name).await, 0);
}

/// Verify that a rejected import applies nothing and exits non-zero.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_rejects_the_whole_file_and_exits_non_zero() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-reject.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // A record type bindizr does not store fails the whole file, and a CI step
    // must not read the rejection as a successful import.
    let output = app
        .run_cli(
            &["zone", "import", &zone_name, "-"],
            Some("www IN A 192.0.2.40\nbox IN TYPE128 \\# 0\n"),
        )
        .await;
    assert!(!output.status.success(), "{output:?}");

    let stdout = String::from_utf8(output.stdout).expect("CLI stdout was not UTF-8");
    assert_eq!(summary_cells(&stdout)[0], "no", "{stdout}");

    // Nothing landed, including the record that was valid on its own.
    let listed = app
        .run_cli_success(&["record", "list", &zone_name], None)
        .await;
    assert!(!listed.contains("192.0.2.40"), "{listed}");
}

/// Verify importing a zone file from standard input.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_from_stdin() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let imported = app
        .run_cli_success(
            &["zone", "import", &zone_name, "-"],
            Some("www IN A 192.0.2.30\nmail IN A 192.0.2.31\n"),
        )
        .await;
    assert!(
        imported.contains("Zone imported successfully"),
        "{imported}"
    );
    assert_eq!(
        summary_row(&imported),
        ["2", "2", "0", "0", "0", "0"],
        "{imported}"
    );

    let dry_run = app
        .run_cli_success(
            &["zone", "import", &zone_name, "-", "--dry-run"],
            Some("extra IN A 192.0.2.32\n"),
        )
        .await;
    assert!(
        dry_run.contains("Dry run completed; no changes applied"),
        "{dry_run}"
    );

    let records = app
        .run_cli_success(
            &[
                "record", "list", &zone_name, "--type", "A", "--output", "json",
            ],
            None,
        )
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

/// Verify that zone import dry run shows the diff via CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_dry_run_shows_the_diff_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("import-dry-run.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // Preview renders a +/-/~ diff and, being a dry run, applies nothing.
    let dry_run = app
        .run_cli_success(
            &["zone", "import", &zone_name, "-", "--dry-run"],
            Some("www IN A 192.0.2.30\nmail IN A 192.0.2.31\n"),
        )
        .await;
    assert!(dry_run.contains("+ www."), "{dry_run}");
    assert!(dry_run.contains("By name and type: +2 -0 ~0"), "{dry_run}");

    let records = app
        .run_cli_success(&["record", "list", &zone_name, "--output", "json"], None)
        .await;
    let records: Value = serde_json::from_str(&records).expect("CLI did not return valid JSON");
    // Only the apex NS seeded at creation exists.
    let names: Vec<&str> = records["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["type"] == "A")
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(names.is_empty(), "records were: {names:?}");
}

/// Verify that zone import from server round-trips over AXFR.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_from_server_round_trips_over_axfr() {
    // The transfer ACL must admit the test's own loopback AXFR.
    let app = TestApp::start_local().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    let zone_name = app.zone_name("axfr-import.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // Keep empty and binary CAA values through the master file and AXFR
    // presentation forms (RFC 8659, Sections 4.1 and 4.2).
    let content = format!(
        concat!(
            "www IN A 192.0.2.30\nmail 300 IN MX 10 mx.example.com.\n",
            "@ IN TXT \"v=spf1 -all\"\n_sip._udp 300 IN SRV 10 5 5060 sip.example.com.\n",
            "@ IN CAA 0 issue \"\"\n@ IN CAA 0 issuewild \"\"\n",
            "@ IN CAA 128 custom \"\\000\\255\\010\\034\\092\"\n",
            "@ IN CAA 0 {} \"{}\"\n",
        ),
        "a".repeat(255),
        "b".repeat(300),
    );
    app.run_cli_success(&["zone", "import", &zone_name, "-"], Some(&content))
        .await;

    let server = format!("127.0.0.1:{}", app.dns_port());
    let dry_run = app
        .run_cli_success(
            &[
                "zone",
                "import",
                &zone_name,
                "--from-server",
                &server,
                "--mode",
                "replace",
                "--dry-run",
            ],
            None,
        )
        .await;
    // A transfer of the zone's own content replaces it with itself.
    assert!(dry_run.contains("By name and type: +0 -0 ~0"), "{dry_run}");

    let applied = app
        .run_cli_success(
            &[
                "zone",
                "import",
                &zone_name,
                "--from-server",
                &server,
                "--mode",
                "replace",
            ],
            None,
        )
        .await;
    assert!(applied.contains("Zone imported successfully"), "{applied}");
    assert_eq!(
        summary_row(&applied),
        ["9", "0", "0", "0", "9", "0"],
        "{applied}"
    );
}
