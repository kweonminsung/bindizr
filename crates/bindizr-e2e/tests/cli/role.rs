use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

/// Verify role grant creation, listing, and revocation through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn role_grant_grants_revoke() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-role.example");
    app.create_zone_cli(&zone_name, "3600").await;
    let (role_name, _) = app.create_scoped_api_token().await;

    let granted = app
        .run_cli_success(&[
            "role",
            "grant",
            &role_name,
            "--zone",
            &zone_name,
            "--actions",
            "record:read,record:create",
            "--types",
            "A,AAAA",
            "--output",
            "json",
        ])
        .await;
    let granted: Value = serde_json::from_str(&granted).expect("CLI did not return valid JSON");
    let granted = &granted["role_grant"];
    assert_eq!(granted["role_name"], role_name);
    assert_eq!(granted["zone_name"], zone_name);
    assert_eq!(granted["record_types"], "A,AAAA");
    let grant_id = granted["id"]
        .as_i64()
        .expect("created grant did not contain an ID")
        .to_string();

    let grants = app.run_cli_success(&["role", "grants", &role_name]).await;
    assert!(grants.contains(&zone_name), "{grants}");
    assert!(grants.contains("record:read,record:create"), "{grants}");

    // The built-in role cannot be changed or deleted.
    let grant_args = ["role", "grant", "admin", "--actions", "zone:read"];
    let refused = app.run_cli(&grant_args).await;
    assert_cli_failure_contains(&grant_args, &refused, "built in");
    let delete_args = ["role", "delete", "admin"];
    let refused = app.run_cli(&delete_args).await;
    assert_cli_failure_contains(&delete_args, &refused, "built in");

    let revoke_args = ["role", "revoke", &role_name, "999999"];
    let refused = app.run_cli(&revoke_args).await;
    assert_cli_failure_contains(&revoke_args, &refused, "not found");

    let revoked = app
        .run_cli_success(&["role", "revoke", &role_name, &grant_id])
        .await;
    assert!(
        revoked.contains("Role grant revoked successfully"),
        "{revoked}"
    );
    let grants = app.run_cli_success(&["role", "grants", &role_name]).await;
    assert!(!grants.contains(&zone_name), "{grants}");

    // The token in the role keeps it from being deleted.
    let delete_args = ["role", "delete", &role_name];
    let refused = app.run_cli(&delete_args).await;
    assert_cli_failure_contains(&delete_args, &refused, "still held");
}
