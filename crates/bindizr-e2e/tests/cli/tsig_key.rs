use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

/// Verify TSIG key creation, listing, retrieval, and deletion through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_create_list_get_delete() {
    let app = TestApp::start().await;

    let created = app
        .run_cli_success(&[
            "tsig-key", "create", "cli-key", "--role", "admin", "--output", "json",
        ])
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    assert_eq!(created["tsig_key"]["name"], "cli-key");
    assert_eq!(created["tsig_key"]["algorithm"], "hmac-sha256");
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
    assert!(
        deleted.contains("TSIG key 'cli-key' deleted successfully"),
        "{deleted}"
    );

    let args = ["tsig-key", "get", "cli-key"];
    let missing = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &missing, "TSIG key with name 'cli-key' not found");
}

/// Verify that a TSIG key names its role, which must exist.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_names_its_role() {
    let app = TestApp::start().await;

    let args = [
        "tsig-key",
        "create",
        "cli-roleless-key",
        "--role",
        "no-such-role",
    ];
    let refused = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &refused, "not found");

    app.run_cli_success(&["role", "create", "cli-key-role"])
        .await;
    app.run_cli_success(&[
        "tsig-key",
        "create",
        "cli-role-key",
        "--role",
        "cli-key-role",
    ])
    .await;
    let listed = app.run_cli_success(&["tsig-key", "list"]).await;
    assert!(listed.contains("cli-key-role"), "{listed}");
    let fetched = app
        .run_cli_success(&["tsig-key", "get", "cli-role-key", "--output", "json"])
        .await;
    let fetched: Value = serde_json::from_str(&fetched).expect("CLI did not return valid JSON");
    assert_eq!(fetched["tsig_key"]["role_name"], "cli-key-role");

    // A key holds its role, not the other way round.
    let args = ["role", "delete", "cli-key-role"];
    let refused = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &refused, "still held");
    app.run_cli_success(&["tsig-key", "delete", "cli-role-key"])
        .await;
    app.run_cli_success(&["role", "delete", "cli-key-role"])
        .await;
}
