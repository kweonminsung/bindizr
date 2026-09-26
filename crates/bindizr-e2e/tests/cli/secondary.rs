use serde_json::Value;

use crate::common::{TestApp, assert_cli_failure_contains};

/// Verify secondary management through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_lifecycle_via_cli() {
    let app = TestApp::start().await;
    let name = format!("{}-cli-ns2", app.namespace());

    let created = app
        .run_cli_success(&[
            "secondary",
            "create",
            &name,
            "--address",
            "ns2.example.net",
            "--output",
            "json",
        ])
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");
    assert_eq!(created["secondary"]["name"], name);
    assert_eq!(created["secondary"]["address"], "ns2.example.net:53");
    assert_eq!(created["secondary"]["enabled"], true);

    let listed = app.run_cli_success(&["secondary", "list"]).await;
    let row = listed
        .lines()
        .find(|line| line.contains(&name))
        .expect("list shows the new secondary");
    assert!(
        row.contains("ns2.example.net:53") && row.contains("yes"),
        "{row}"
    );

    let updated = app
        .run_cli_success(&[
            "secondary",
            "update",
            &name,
            "--address",
            "192.0.2.7:5300",
            "--enabled",
            "false",
            "--output",
            "json",
        ])
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");
    assert_eq!(updated["secondary"]["address"], "192.0.2.7:5300");
    assert_eq!(updated["secondary"]["enabled"], false);

    let fetched = app.run_cli_success(&["secondary", "get", &name]).await;
    assert!(
        fetched.contains("192.0.2.7:5300") && fetched.contains("no"),
        "{fetched}"
    );

    // A NOTIFY key is named on the row and cleared with an empty name.
    let key_name = format!("{}-notify", app.namespace());
    app.run_cli_success(&["tsig-key", "create", &key_name])
        .await;
    let keyed = app
        .run_cli_success(&["secondary", "update", &name, "--notify-key", &key_name])
        .await;
    assert!(keyed.contains(&key_name), "{keyed}");
    let cleared = app
        .run_cli_success(&[
            "secondary",
            "update",
            &name,
            "--notify-key",
            "",
            "--output",
            "json",
        ])
        .await;
    let cleared: Value = serde_json::from_str(&cleared).expect("CLI did not return valid JSON");
    assert_eq!(cleared["secondary"]["notify_key_name"], Value::Null);
    app.run_cli_success(&["tsig-key", "delete", &key_name])
        .await;

    let args = ["secondary", "update", &name];
    let nothing = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &nothing, "nothing to update");

    let deleted = app.run_cli_success(&["secondary", "delete", &name]).await;
    assert!(
        deleted.contains(&format!("Secondary '{name}' deleted successfully")),
        "{deleted}"
    );

    let args = ["secondary", "get", &name];
    let missing = app.run_cli(&args).await;
    assert_cli_failure_contains(
        &args,
        &missing,
        &format!("Secondary with name '{name}' not found"),
    );
}
