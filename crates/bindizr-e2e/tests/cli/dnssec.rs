use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_lifecycle_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let enabled = app
        .run_cli_success(&["zone", "dnssec", "enable", &zone_name])
        .await;
    assert!(enabled.contains("DNSSEC enabled successfully"));
    assert!(enabled.contains("DNSSEC enabled"));

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    assert!(status.contains("DNSSEC enabled"));
    // The keys table row is `ID ROLE STATE ELIGIBLE-AT ALGORITHM KEY_TAG
    // DNSKEY`; an active key's ELIGIBLE-AT renders as `-`.
    let key_row = status
        .lines()
        .find(|line| line.contains("ecdsap256sha256"))
        .expect("status lists the signing key");
    let key_tag = key_row
        .split_whitespace()
        .nth(5)
        .expect("key row carries a key tag");
    assert!(key_tag.parse::<u32>().expect("key tag is numeric") > 0);

    let ds = app
        .run_cli_success(&["zone", "dnssec", "ds", &zone_name])
        .await;
    assert!(ds.contains(&format!("IN DS {key_tag} ")), "{ds}");

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

    let signed = app
        .run_cli_success(&["zone", "dnssec", "sign", &zone_name])
        .await;
    assert!(signed.contains("Zone signed successfully"));

    let disabled = app
        .run_cli_success(&["zone", "dnssec", "disable", &zone_name])
        .await;
    assert!(disabled.contains("DNSSEC disabled successfully"));

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    assert!(status.contains("DNSSEC disabled"));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_dnssec_nsec3_rollover_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("dnssec-roll-cli.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let enabled = app
        .run_cli_success(&["zone", "dnssec", "enable", &zone_name, "--denial", "nsec3"])
        .await;
    assert!(enabled.contains("DNSSEC enabled successfully"));
    assert!(enabled.contains("NSEC3 denial"));

    let started = app
        .run_cli_success(&["zone", "dnssec", "rollover", "start", &zone_name])
        .await;
    assert!(started.contains("Key rollover started successfully"));

    let status = app
        .run_cli_success(&["zone", "dnssec", "status", &zone_name])
        .await;
    assert!(status.contains("NSEC3 denial"));
    assert!(status.contains("published"), "{status}");
    assert!(status.contains("active"), "{status}");

    // The API test covers the far side of the hold-down wait.
    let ds_seen = app
        .run_cli(&["zone", "dnssec", "rollover", "ds-seen", &zone_name])
        .await;
    assert!(!ds_seen.status.success());
}
