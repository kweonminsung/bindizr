use crate::common::{TestApp, assert_cli_failure_contains};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tsig_key_create_list_get_delete() {
    let app = TestApp::start().await;

    let created = app
        .run_cli_success(&["tsig-key", "create", "--name", "cli-key"])
        .await;
    assert!(created.contains("TSIG key created successfully"));
    assert!(created.contains("Name: cli-key"));
    assert!(created.contains("Algorithm: hmac-sha256"));
    assert!(created.contains("Secret: "));

    let listed = app.run_cli_success(&["tsig-key", "list"]).await;
    assert!(listed.contains("cli-key"));
    assert!(!listed.contains("Secret: "));

    let fetched = app.run_cli_success(&["tsig-key", "get", "cli-key"]).await;
    assert!(fetched.contains("Secret: "));

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
async fn zone_tsig_policy_add_list_remove() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-tsig.example");

    app.create_zone_cli(&zone_name, "3600").await;

    app.run_cli_success(&["tsig-key", "create", "--name", "cli-policy-key"])
        .await;

    let added = app
        .run_cli_success(&[
            "tsig-policy",
            "add",
            &zone_name,
            "--key",
            "cli-policy-key",
            "--pattern",
            "*.dyn",
            "--types",
            "A,TXT",
        ])
        .await;
    assert!(added.contains("TSIG policy created successfully"));

    let listed = app
        .run_cli_success(&["tsig-policy", "list", &zone_name])
        .await;
    assert!(listed.contains("cli-policy-key"));
    assert!(listed.contains("*.dyn"));
    assert!(listed.contains("A,TXT"));

    // The key is in use, so deleting it is refused with a clear error.
    let delete_args = ["tsig-key", "delete", "cli-policy-key"];
    let refused = app.run_cli(&delete_args).await;
    assert_cli_failure_contains(&delete_args, &refused, "referenced by 1 TSIG policy");

    // The first whitespace-separated column of the list output is the policy ID.
    let policy_id = listed
        .lines()
        .find(|line| line.contains("cli-policy-key"))
        .and_then(|line| line.split_whitespace().next())
        .expect("policy row not found")
        .to_string();

    let removed = app
        .run_cli_success(&["tsig-policy", "remove", &zone_name, &policy_id])
        .await;
    assert!(removed.contains("TSIG policy deleted successfully"));

    app.run_cli_success(&["tsig-key", "delete", "cli-policy-key"])
        .await;
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn global_tsig_key_create_list_delete() {
    let app = TestApp::start().await;

    let created = app
        .run_cli_success(&["tsig-key", "create", "--name", "cli-global-key", "--global"])
        .await;
    assert!(created.contains("TSIG key created successfully"));
    assert!(created.contains("Global: yes"));
    assert!(created.contains("Warning: this key can update every zone"));

    let listed = app.run_cli_success(&["tsig-key", "list"]).await;
    assert!(listed.contains("cli-global-key"));
    assert!(listed.contains("yes"));

    let fetched = app
        .run_cli_success(&["tsig-key", "get", "cli-global-key"])
        .await;
    assert!(fetched.contains("Global: yes"));

    app.run_cli_success(&["tsig-key", "delete", "cli-global-key"])
        .await;
}
