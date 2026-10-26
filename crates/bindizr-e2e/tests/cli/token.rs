use crate::common;
use crate::common::TestApp;

/// Verify that token create rejects duplicate name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_create_rejects_duplicate_name() {
    let app = TestApp::start().await;
    let (name, _) = app.create_api_token().await;

    let output = app
        .run_cli(&["token", "create", &name, "--role", "admin"], None)
        .await;

    assert!(!output.status.success());
}

/// Verify that a token needs a role that exists.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_create_needs_an_existing_role() {
    let app = TestApp::start().await;
    let name = app.zone_name("roleless");

    let args = ["token", "create", &name, "--role", "no-such-role"];
    let refused = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(&args, &refused, "not found");
}
