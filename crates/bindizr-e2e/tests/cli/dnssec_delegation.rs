//! The parent side of DNSSEC over the CLI: `dnssec set --parent-ns-addrs`,
//! `check-ds`, and the DS gate on `disable`.

use crate::common::{FakeParent, ServedDs, TestApp, assert_cli_failure_contains};

async fn dnssec_status(app: &TestApp, zone_name: &str) -> serde_json::Value {
    let status = app
        .run_cli_success(&["dnssec", "status", zone_name, "--output", "json"])
        .await;
    serde_json::from_str(&status).expect("CLI did not return valid JSON")
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_parent_ds_check_via_cli() {
    let app = TestApp::start_local().await;
    let parent = FakeParent::start();
    let parent_addr = parent.addr();
    let zone_name = app.zone_name("dnssec-parent-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let enabled = app
        .run_cli_success(&[
            "dnssec",
            "enable",
            &zone_name,
            "--parent-ns-addrs",
            &parent_addr,
        ])
        .await;
    assert!(
        enabled.contains(&format!("Parent nameservers: {parent_addr}")),
        "{enabled}"
    );
    let status = dnssec_status(&app, &zone_name).await;
    let key_tag = status["dnssec"]["keys"][0]["key_tag"].as_u64().unwrap() as u16;
    parent.set_ds(vec![ServedDs::from_status(
        &status["dnssec"],
        key_tag,
        3600,
    )]);

    let disable_args = ["dnssec", "disable", &zone_name];
    let refused = app.run_cli(&disable_args).await;
    assert_cli_failure_contains(&disable_args, &refused, "still serves DS records");

    let checked = app
        .run_cli_success(&["dnssec", "check-ds", &zone_name])
        .await;
    assert!(
        checked.contains(&format!(
            "Parent DS: key tag {key_tag} served by {parent_addr} (TTL 3600s)"
        )),
        "{checked}"
    );
    assert!(
        checked.contains(&format!("  {key_tag} (csk, active): at parent")),
        "{checked}"
    );

    let set = app
        .run_cli_success(&[
            "dnssec",
            "set",
            &zone_name,
            "--parent-ns-addrs",
            &parent_addr,
        ])
        .await;
    assert!(
        set.contains(&format!("Parent nameservers: {parent_addr}")),
        "{set}"
    );

    parent.set_ds(Vec::new());
    let checked = app
        .run_cli_success(&["dnssec", "check-ds", &zone_name])
        .await;
    assert!(
        checked.contains(&format!("Parent DS: none served by {parent_addr}")),
        "{checked}"
    );
    let disabled = app.run_cli_success(&disable_args).await;
    assert!(disabled.contains("DNSSEC disabled successfully"));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_disable_skip_ds_check_via_cli() {
    let app = TestApp::start_local().await;
    let zone_name = app.zone_name("dnssec-skip-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;
    // Nothing listens on the loopback discard port, so the parent never answers.
    app.run_cli_success(&[
        "dnssec",
        "enable",
        &zone_name,
        "--parent-ns-addrs",
        "127.0.0.1:9",
    ])
    .await;

    let disable_args = ["dnssec", "disable", &zone_name];
    let refused = app.run_cli(&disable_args).await;
    assert_cli_failure_contains(&disable_args, &refused, "could not verify");

    let disabled = app
        .run_cli_success(&["dnssec", "disable", &zone_name, "--skip-ds-check"])
        .await;
    assert!(disabled.contains("DNSSEC disabled successfully"));
}
