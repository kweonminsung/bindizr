use crate::{
    cli::common::read_signing_key_tag,
    common::{TestApp, assert_cli_failure_contains},
};

mod delegation;
mod keys;

/// Verify the DNSSEC lifecycle through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_lifecycle_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let enabled = app
        .run_cli_success(&[
            "dnssec",
            "enable",
            &zone_name,
            "--parent-ns-addrs",
            "127.0.0.1:9",
        ])
        .await;
    assert!(enabled.contains("DNSSEC enabled"), "{enabled}");

    let status = app.run_cli_success(&["dnssec", "status", &zone_name]).await;
    assert!(status.contains("DNSSEC enabled"));
    let key_tag = read_signing_key_tag(&app, &zone_name).await;
    assert!(key_tag > 0);

    assert!(status.contains(&format!("IN DS {key_tag} ")), "{status}");

    // Same algorithm, denial, and key layout as `default`: the move only
    // changes the timing, so no rollover starts.
    let policy_name = format!("{}-long", app.namespace());
    app.run_cli_success(&[
        "dnssec-policy",
        "create",
        &policy_name,
        "--signature-validity-days",
        "30",
        "--zsk-lifetime-days",
        "90",
    ])
    .await;
    let moved = app
        .run_cli_success(&["dnssec", "set", &zone_name, "--policy", &policy_name])
        .await;
    // The policy row of the status output carries the new timing.
    assert!(
        moved.contains(&policy_name) && moved.contains("30d") && moved.contains("90d"),
        "{moved}"
    );
    assert!(!moved.contains("published"), "{moved}");

    let signed_export = app
        .run_cli_success(&["zone", "export", &zone_name, "--signed"])
        .await;
    assert!(
        signed_export.contains("\tIN\tDNSKEY\t257 3 "),
        "{signed_export}"
    );
    assert!(
        signed_export.contains("\tIN\tRRSIG\tSOA "),
        "{signed_export}"
    );

    let withdrawn = app
        .run_cli_success(&["dnssec", "withdraw", "start", &zone_name])
        .await;
    assert!(withdrawn.contains("DS withdrawal published"), "{withdrawn}");
    let cancelled = app
        .run_cli_success(&["dnssec", "withdraw", "cancel", &zone_name])
        .await;
    assert!(
        !cancelled.contains("DS withdrawal published"),
        "{cancelled}"
    );

    let signed = app.run_cli_success(&["dnssec", "sign", &zone_name]).await;
    assert!(signed.contains("Zone signed successfully"));

    let disabled = app
        .run_cli_success(&["dnssec", "disable", &zone_name, "--skip-ds-check"])
        .await;
    assert!(disabled.contains("DNSSEC disabled successfully"));

    let status = app.run_cli_success(&["dnssec", "status", &zone_name]).await;
    assert!(status.contains("DNSSEC disabled"));
}

/// Verify DNSSEC rollover with NSEC3 through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_nsec3_rollover_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-roll-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let policy_name = format!("{}-nsec3", app.namespace());
    app.run_cli_success(&["dnssec-policy", "create", &policy_name, "--denial", "nsec3"])
        .await;
    let enabled = app
        .run_cli_success(&[
            "dnssec",
            "enable",
            &zone_name,
            "--policy",
            &policy_name,
            "--parent-ns-addrs",
            "127.0.0.1:9",
        ])
        .await;
    assert!(enabled.contains("NSEC3 denial"), "{enabled}");

    let started = app
        .run_cli_success(&["dnssec", "rollover", "start", &zone_name])
        .await;
    // The pre-published replacement key joins the key table.
    assert!(started.contains("published"), "{started}");

    let status = app.run_cli_success(&["dnssec", "status", &zone_name]).await;
    assert!(status.contains("NSEC3 denial"));
    assert!(status.contains("published"), "{status}");
    assert!(status.contains("active"), "{status}");

    // The API test covers the far side of the hold-down wait;
    // `--skip-ds-check` skips only the parent check, never the hold-down.
    let ds_seen = app
        .run_cli(&["dnssec", "rollover", "ds-seen", &zone_name])
        .await;
    assert!(!ds_seen.status.success());
    let unchecked = [
        "dnssec",
        "rollover",
        "ds-seen",
        &zone_name,
        "--skip-ds-check",
    ];
    let ds_seen = app.run_cli(&unchecked).await;
    assert_cli_failure_contains(&unchecked, &ds_seen, "must stay published");

    // No parent stands in, so both skips promote at once.
    let promoted = app
        .run_cli_success(&[
            "dnssec",
            "rollover",
            "ds-seen",
            &zone_name,
            "--skip-ds-check",
            "--skip-holddown",
        ])
        .await;
    assert!(promoted.contains("retired"), "{promoted}");
    assert!(!promoted.contains("published"), "{promoted}");
}
