use crate::{cli::common::read_signing_key_tag, common::TestApp};

mod delegation;
mod keys;
mod rollover;

/// Verify the DNSSEC lifecycle through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_supports_enable_sign_and_disable_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let enabled = app
        .run_cli_success(
            &[
                "dnssec",
                "enable",
                &zone_name,
                "--parent-ns-addrs",
                "127.0.0.1:9",
            ],
            None,
        )
        .await;
    assert!(enabled.contains("DNSSEC enabled"), "{enabled}");

    let status = app
        .run_cli_success(&["dnssec", "status", &zone_name], None)
        .await;
    assert!(status.contains("DNSSEC enabled"));
    let key_tag = read_signing_key_tag(&app, &zone_name).await;
    assert!(key_tag > 0);

    assert!(status.contains(&format!("IN DS {key_tag} ")), "{status}");

    // Same algorithm, denial, and key layout as `default`: the move only
    // changes the timing, so no rollover starts.
    let policy_name = format!("{}-long", app.namespace());
    app.run_cli_success(
        &[
            "dnssec-policy",
            "create",
            &policy_name,
            "--signature-validity-days",
            "30",
            "--zsk-lifetime-days",
            "90",
        ],
        None,
    )
    .await;
    let moved = app
        .run_cli_success(
            &["dnssec", "set", &zone_name, "--policy", &policy_name],
            None,
        )
        .await;
    // The policy row of the status output carries the new timing.
    assert!(
        moved.contains(&policy_name) && moved.contains("30d") && moved.contains("90d"),
        "{moved}"
    );
    assert!(!moved.contains("published"), "{moved}");

    let signed_export = app
        .run_cli_success(&["zone", "export", &zone_name, "--signed"], None)
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
        .run_cli_success(&["dnssec", "withdraw", "start", &zone_name], None)
        .await;
    assert!(withdrawn.contains("DS withdrawal published"), "{withdrawn}");
    let cancelled = app
        .run_cli_success(&["dnssec", "withdraw", "cancel", &zone_name], None)
        .await;
    assert!(
        !cancelled.contains("DS withdrawal published"),
        "{cancelled}"
    );

    let signed = app
        .run_cli_success(&["dnssec", "sign", &zone_name], None)
        .await;
    assert!(signed.contains("Zone signed successfully"));

    let disabled = app
        .run_cli_success(&["dnssec", "disable", &zone_name, "--skip-ds-check"], None)
        .await;
    assert!(disabled.contains("DNSSEC disabled successfully"));

    let status = app
        .run_cli_success(&["dnssec", "status", &zone_name], None)
        .await;
    assert!(status.contains("DNSSEC disabled"));
}
