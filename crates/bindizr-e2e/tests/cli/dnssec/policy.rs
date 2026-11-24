use serde_json::Value;

use crate::common::TestApp;

/// Verify that the CLI manages DNSSEC policies.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_policy_supports_create_update_and_delete() {
    let app = TestApp::start().await;
    let policy_name = format!("{}-cli", app.namespace());

    let created = app
        .run_cli_success(
            &[
                "dnssec",
                "policy",
                "create",
                &policy_name,
                "--algorithm",
                "ecdsap384sha384",
                "--key-layout",
                "split",
                "--signature-validity-days",
                "21",
                "--signature-refresh-days",
                "7",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    let created = &created["dnssec_policy"];

    assert_eq!(created["name"], policy_name);
    assert_eq!(created["algorithm"], "ecdsap384sha384");
    assert_eq!(created["key_layout"], "split");
    assert_eq!(created["signature_validity_days"], 21);
    assert_eq!(created["signature_refresh_days"], 7);

    let listed = app
        .run_cli_success(&["dnssec", "policy", "list"], None)
        .await;
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
        .run_cli_success(
            &[
                "dnssec",
                "policy",
                "update",
                &policy_name,
                "--zsk-lifetime-days",
                "60",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    let updated = &updated["dnssec_policy"];

    assert_eq!(updated["zsk_lifetime_days"], 60);

    // The untouched fields keep their values.
    assert_eq!(updated["signature_validity_days"], 21);
    assert_eq!(updated["signature_refresh_days"], 7);

    let fetched = app
        .run_cli_success(&["dnssec", "policy", "get", &policy_name], None)
        .await;

    assert!(fetched.contains("60d"), "{fetched}");

    let deleted = app
        .run_cli_success(&["dnssec", "policy", "delete", &policy_name], None)
        .await;

    assert!(deleted.contains("deleted successfully"), "{deleted}");

    let missing = app
        .run_cli(&["dnssec", "policy", "get", &policy_name], None)
        .await;

    assert!(!missing.status.success());
}
