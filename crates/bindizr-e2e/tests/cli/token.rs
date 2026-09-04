use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_create_rejects_duplicate_name() {
    let app = TestApp::start().await;
    let (name, _) = app.create_api_token().await;

    let output = app.run_cli(&["token", "create", "--name", &name]).await;
    assert!(!output.status.success());
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_grant_grants_revoke() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-token.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let (scoped_name, _) = app.create_scoped_api_token().await;

    let granted = app
        .run_cli_success(&[
            "token",
            "grant",
            &scoped_name,
            &zone_name,
            "--types",
            "A,AAAA",
            "--output",
            "json",
        ])
        .await;
    let granted: Value = serde_json::from_str(&granted).expect("CLI did not return valid JSON");
    assert_eq!(granted["api_token"], scoped_name);
    assert_eq!(granted["zone_name"], zone_name);
    assert_eq!(granted["record_types"], "A,AAAA");
    let grant_id = granted["id"]
        .as_i64()
        .expect("created grant did not contain an ID")
        .to_string();

    let by_token = app
        .run_cli_success(&["token", "grants", &scoped_name])
        .await;
    assert!(by_token.contains(&zone_name), "{by_token}");

    let by_zone = app
        .run_cli_success(&["token", "grants", "--zone", &zone_name])
        .await;
    assert!(by_zone.contains(&scoped_name), "{by_zone}");

    // A global token already covers every zone, so it cannot be granted one.
    let (global_name, _) = app.create_api_token().await;
    let grant_args = ["token", "grant", &global_name, &zone_name];
    let refused = app.run_cli(&grant_args).await;
    assert_cli_failure_contains(&grant_args, &refused, "is global");

    // A grant id is only reachable under the token that holds it.
    let revoke_args = ["token", "revoke", &global_name, &grant_id];
    let refused = app.run_cli(&revoke_args).await;
    assert_cli_failure_contains(&revoke_args, &refused, "not found");

    let revoked = app
        .run_cli_success(&["token", "revoke", &scoped_name, &grant_id])
        .await;
    assert!(
        revoked.contains("Token grant revoked successfully"),
        "{revoked}"
    );

    let by_token = app
        .run_cli_success(&["token", "grants", &scoped_name])
        .await;
    assert!(!by_token.contains(&zone_name), "{by_token}");
}
