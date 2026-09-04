use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_create_list_get_delete() {
    let app = TestApp::start().await;

    let created = app
        .run_cli_success(&[
            "tsig-key", "create", "--name", "cli-key", "--output", "json",
        ])
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    assert_eq!(created["name"], "cli-key");
    assert_eq!(created["algorithm"], "hmac-sha256");
    let secret = created["secret"]
        .as_str()
        .expect("create discloses the secret")
        .to_string();

    // The listing carries every column but the secret.
    let listed = app.run_cli_success(&["tsig-key", "list"]).await;
    assert!(listed.contains("cli-key"));
    assert!(!listed.contains(&secret));

    let fetched = app.run_cli_success(&["tsig-key", "get", "cli-key"]).await;
    assert!(fetched.contains(&secret));

    let deleted = app
        .run_cli_success(&["tsig-key", "delete", "cli-key"])
        .await;
    assert!(deleted.contains("TSIG key deleted successfully"));

    let args = ["tsig-key", "get", "cli-key"];
    let missing = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &missing, "TSIG key with name 'cli-key' not found");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_grant_grants_revoke() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-tsig.example");

    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&["tsig-key", "create", "--name", "cli-grant-key"])
        .await;

    let granted = app
        .run_cli_success(&[
            "tsig-key",
            "grant",
            "cli-grant-key",
            &zone_name,
            "--pattern",
            "*.dyn",
            "--types",
            "A,TXT",
            "--output",
            "json",
        ])
        .await;
    let granted: Value = serde_json::from_str(&granted).expect("CLI did not return valid JSON");
    assert_eq!(granted["tsig_key"], "cli-grant-key");
    assert_eq!(granted["zone_name"], zone_name);
    assert_eq!(granted["record_name_pattern"], "*.dyn");
    let grant_id = granted["id"]
        .as_i64()
        .expect("created grant did not contain an ID")
        .to_string();

    let by_key = app
        .run_cli_success(&["tsig-key", "grants", "cli-grant-key"])
        .await;
    assert!(by_key.contains(&zone_name), "{by_key}");
    assert!(by_key.contains("*.dyn"), "{by_key}");
    assert!(by_key.contains("A,TXT"), "{by_key}");

    let by_zone = app
        .run_cli_success(&["tsig-key", "grants", "--zone", &zone_name])
        .await;
    assert!(by_zone.contains("cli-grant-key"), "{by_zone}");

    // The key still holds a grant, so deleting it is refused with a clear error.
    let delete_args = ["tsig-key", "delete", "cli-grant-key"];
    let refused = app.run_cli(&delete_args).await;
    assert_cli_failure_contains(&delete_args, &refused, "still holds 1 grant");

    let revoked = app
        .run_cli_success(&["tsig-key", "revoke", "cli-grant-key", &grant_id])
        .await;
    assert!(
        revoked.contains("TSIG grant revoked successfully"),
        "{revoked}"
    );

    app.run_cli_success(&["tsig-key", "delete", "cli-grant-key"])
        .await;
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn global_tsig_key_create_list_delete() {
    let app = TestApp::start().await;

    let args = ["tsig-key", "create", "--name", "cli-global-key", "--global"];
    let created = app.run_cli(&args).await;
    assert!(created.status.success(), "{created:?}");
    let stdout = String::from_utf8(created.stdout).expect("CLI stdout was not UTF-8");
    assert!(stdout.contains("cli-global-key"), "{stdout}");
    // The warning goes to stderr so `--output json` stays parseable.
    let stderr = String::from_utf8(created.stderr).expect("CLI stderr was not UTF-8");
    assert!(
        stderr.contains("Warning: this key can update every zone"),
        "{stderr}"
    );

    let listed = app.run_cli_success(&["tsig-key", "list"]).await;
    assert!(listed.contains("cli-global-key"));
    assert!(listed.contains("yes"));

    let fetched = app
        .run_cli_success(&["tsig-key", "get", "cli-global-key", "--output", "json"])
        .await;
    let fetched: Value = serde_json::from_str(&fetched).expect("CLI did not return valid JSON");
    assert_eq!(fetched["global"], true);

    app.run_cli_success(&["tsig-key", "delete", "cli-global-key"])
        .await;
}
