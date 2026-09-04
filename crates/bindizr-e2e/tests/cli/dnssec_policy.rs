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
        ])
        .await;
    assert!(created.contains("DNSSEC policy created successfully"));
    assert!(
        created.contains(&format!("Name: {policy_name}")),
        "{created}"
    );
    assert!(created.contains("Algorithm: ecdsap384sha384"), "{created}");
    assert!(created.contains("Keys: KSK/ZSK"), "{created}");
    assert!(
        created.contains("Signature validity: 21d (re-sign with 7d left)"),
        "{created}"
    );

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
        ])
        .await;
    assert!(updated.contains("DNSSEC policy updated successfully"));
    assert!(updated.contains("ZSK lifetime: 60d"), "{updated}");
    // The untouched fields keep their values.
    assert!(
        updated.contains("Signature validity: 21d (re-sign with 7d left)"),
        "{updated}"
    );

    let got = app
        .run_cli_success(&["dnssec-policy", "get", &policy_name])
        .await;
    assert!(got.contains("ZSK lifetime: 60d"), "{got}");

    let deleted = app
        .run_cli_success(&["dnssec-policy", "delete", &policy_name])
        .await;
    assert!(deleted.contains("DNSSEC policy deleted successfully"));

    let missing = app.run_cli(&["dnssec-policy", "get", &policy_name]).await;
    assert!(!missing.status.success());
}
