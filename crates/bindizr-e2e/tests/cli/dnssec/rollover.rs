use crate::common::{TestApp, assert_cli_failure_contains};

/// Verify DNSSEC rollover with NSEC3 through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_rolls_nsec3_keys_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-roll-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let policy_name = format!("{}-nsec3", app.namespace());
    app.run_cli_success(
        &["dnssec-policy", "create", &policy_name, "--denial", "nsec3"],
        None,
    )
    .await;
    let enabled = app
        .run_cli_success(
            &[
                "dnssec",
                "enable",
                &zone_name,
                "--policy",
                &policy_name,
                "--parent-ns-addrs",
                "127.0.0.1:9",
            ],
            None,
        )
        .await;
    assert!(enabled.contains("NSEC3 denial"), "{enabled}");

    let started = app
        .run_cli_success(&["dnssec", "rollover", "start", &zone_name], None)
        .await;
    // The pre-published replacement key joins the key table.
    assert!(started.contains("published"), "{started}");

    let status = app
        .run_cli_success(&["dnssec", "status", &zone_name], None)
        .await;
    assert!(status.contains("NSEC3 denial"));
    assert!(status.contains("published"), "{status}");
    assert!(status.contains("active"), "{status}");

    // The API test covers the far side of the hold-down wait;
    // `--skip-ds-check` skips only the parent check, never the hold-down.
    let ds_seen = app
        .run_cli(&["dnssec", "rollover", "ds-seen", &zone_name], None)
        .await;
    assert!(!ds_seen.status.success());
    let unchecked = [
        "dnssec",
        "rollover",
        "ds-seen",
        &zone_name,
        "--skip-ds-check",
    ];
    let ds_seen = app.run_cli(&unchecked, None).await;
    assert_cli_failure_contains(&unchecked, &ds_seen, "must stay published");

    // No parent stands in, so both skips promote at once.
    let promoted = app
        .run_cli_success(
            &[
                "dnssec",
                "rollover",
                "ds-seen",
                &zone_name,
                "--skip-ds-check",
                "--skip-holddown",
            ],
            None,
        )
        .await;
    assert!(promoted.contains("retired"), "{promoted}");
    assert!(!promoted.contains("published"), "{promoted}");
}
