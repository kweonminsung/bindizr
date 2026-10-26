use serde_json::Value;

use crate::common;
use crate::common::TestApp;

/// Verify secondary management through the CLI.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_supports_create_update_and_delete_via_cli() {
    let app = TestApp::start().await;
    let name = format!("{}-cli-ns2", app.namespace());

    let created = app
        .run_cli_success(
            &[
                "secondary",
                "create",
                &name,
                "--address",
                "ns2.example.net",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let created: Value = serde_json::from_str(&created).expect("CLI did not return valid JSON");

    assert_eq!(created["secondary"]["name"], name);
    assert_eq!(created["secondary"]["address"], "ns2.example.net:53");
    assert_eq!(created["secondary"]["enabled"], true);

    let listed = app.run_cli_success(&["secondary", "list"], None).await;
    let row = listed
        .lines()
        .find(|line| line.contains(&name))
        .expect("list shows the new secondary");

    assert!(
        row.contains("ns2.example.net:53") && row.contains("yes"),
        "{row}"
    );

    let updated = app
        .run_cli_success(
            &[
                "secondary",
                "update",
                &name,
                "--address",
                "192.0.2.7:5300",
                "--enabled",
                "false",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let updated: Value = serde_json::from_str(&updated).expect("CLI did not return valid JSON");

    assert_eq!(updated["secondary"]["address"], "192.0.2.7:5300");
    assert_eq!(updated["secondary"]["enabled"], false);

    let fetched = app
        .run_cli_success(&["secondary", "get", &name], None)
        .await;

    assert!(
        fetched.contains("192.0.2.7:5300") && fetched.contains("no"),
        "{fetched}"
    );

    // A NOTIFY key is named on the row and cleared with an empty name.
    let key_name = format!("{}-notify", app.namespace());

    app.run_cli_success(&["tsig-key", "create", &key_name, "--role", "admin"], None)
        .await;
    let keyed = app
        .run_cli_success(
            &["secondary", "update", &name, "--notify-key", &key_name],
            None,
        )
        .await;

    assert!(keyed.contains(&key_name), "{keyed}");

    let cleared = app
        .run_cli_success(
            &[
                "secondary",
                "update",
                &name,
                "--notify-key",
                "",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let cleared: Value = serde_json::from_str(&cleared).expect("CLI did not return valid JSON");

    assert_eq!(cleared["secondary"]["notify_key_name"], Value::Null);

    app.run_cli_success(&["tsig-key", "delete", &key_name], None)
        .await;

    let args = ["secondary", "update", &name];

    let nothing = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(&args, &nothing, "nothing to update");

    let deleted = app
        .run_cli_success(&["secondary", "delete", &name], None)
        .await;

    assert!(
        deleted.contains(&format!("Secondary '{name}' deleted successfully")),
        "{deleted}"
    );

    let args = ["secondary", "get", &name];

    let missing = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(
        &args,
        &missing,
        &format!("secondary with name '{name}' not found"),
    );
}
