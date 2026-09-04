use serde_json::Value;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_policy_lifecycle_via_cli() {
    let app = TestApp::start().await;
    let policy_name = format!("{}-cli", app.namespace());

    let created = app
        .run_cli_success(&[
            "dnssec-policy",
            "create",
            "--name",
            &policy_name,
            "--algorithm",
            "ecdsap384sha384",
            "--split-keys",
            "--signature-validity-days",
            "21",
            "--signature-refresh-days",
            "7",
            "--output",
            "json",
        ])
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    assert_eq!(created["name"], policy_name);
    assert_eq!(created["algorithm"], "ecdsap384sha384");
    assert_eq!(created["split_keys"], true);
    assert_eq!(created["signature_validity_days"], 21);
    assert_eq!(created["signature_refresh_days"], 7);

    let listed = app.run_cli_success(&["dnssec-policy", "list"]).await;
    let row = listed
        .lines()
        .find(|line| line.contains(&policy_name))
        .expect("list shows the new policy");
    assert!(
        row.contains("ecdsap384sha384") && row.contains("KSK/ZSK"),
        "{row}"
    );
    assert!(listed.contains("default"), "{listed}");

    let updated = app
        .run_cli_success(&[
            "dnssec-policy",
            "update",
            &policy_name,
            "--zsk-lifetime-days",
            "60",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    assert_eq!(updated["zsk_lifetime_days"], 60);
    // The untouched fields keep their values.
    assert_eq!(updated["signature_validity_days"], 21);
    assert_eq!(updated["signature_refresh_days"], 7);

    let got = app
        .run_cli_success(&["dnssec-policy", "get", &policy_name])
        .await;
    assert!(got.contains("60d"), "{got}");

    let deleted = app
        .run_cli_success(&["dnssec-policy", "delete", &policy_name])
        .await;
    assert!(deleted.contains("DNSSEC policy deleted successfully"));

    let missing = app.run_cli(&["dnssec-policy", "get", &policy_name]).await;
    assert!(!missing.status.success());
}
