use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::common;
use crate::common::TestApp;

/// Verify that `log activity` shows socket changes without an actor and
/// narrows by entity and name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn log_activity_shows_socket_changes() {
    let app = TestApp::start().await;
    let name = format!("{}-cli-audited", app.namespace());

    app.run_cli_success(&["role", "create", &name], None).await;
    app.run_cli_success(&["token", "create", &name, "--role", &name], None)
        .await;
    app.run_cli_success(&["token", "delete", &name], None).await;

    let listed = app
        .run_cli_success(
            &[
                "log",
                "activity",
                "--entity",
                "token",
                "--name",
                &name,
                "--sort",
                "created_at",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");

    assert_eq!(listed["pagination"]["total"], 2, "{listed}");
    let items = listed["items"].as_array().expect("log list has items");

    assert_eq!(items[0]["operation"], "token.delete");
    assert_eq!(items[1]["operation"], "token.create");

    for log in items {
        assert_eq!(log["target"]["name"], name);
        assert!(log["created_at"].is_string(), "{log}");
        // A socket command is the daemon's own user: no token names it.
        assert_eq!(log["source"], "socket");
        assert!(log["actor"].is_null(), "{log}");
    }

    // Without an entity, the role's own creation is listed beside its token's;
    // DETAIL says what each set.
    let table = app
        .run_cli_success(&["log", "activity", "--name", &name], None)
        .await;
    let rows: Vec<&str> = table.lines().filter(|line| line.contains(&name)).collect();

    assert_eq!(rows.len(), 3, "{table}");
    assert!(
        rows.iter()
            .any(|row| row.contains("role") && row.contains("create"))
    );
    assert!(rows.iter().all(|row| row.contains("socket")), "{table}");
    assert!(
        rows.iter().any(|row| row.contains("expires_at never")),
        "{table}"
    );

    // Sort by canonical operation in ascending order.
    let sorted = app
        .run_cli_success(
            &[
                "log",
                "activity",
                "--name",
                &name,
                "--sort",
                "operation",
                "--order",
                "asc",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let sorted: Value = serde_json::from_str(&sorted).expect("CLI did not return valid JSON");
    let operations: Vec<&str> = sorted["items"]
        .as_array()
        .expect("log list has items")
        .iter()
        .map(|log| log["operation"].as_str().expect("log row has an operation"))
        .collect();

    assert_eq!(
        operations,
        ["role.create", "token.create", "token.delete"],
        "{sorted}"
    );

    // A span ago reaches the daemon as a time: everything is newer than an
    // hour ago, and nothing is older.
    let recent = app
        .run_cli_success(
            &[
                "log", "activity", "--name", &name, "--since", "1h", "--output", "json",
            ],
            None,
        )
        .await;
    let recent: Value = serde_json::from_str(&recent).expect("CLI did not return valid JSON");

    assert_eq!(recent["pagination"]["total"], 3, "{recent}");

    let older = app
        .run_cli_success(
            &[
                "log", "activity", "--name", &name, "--until", "1h", "--output", "json",
            ],
            None,
        )
        .await;
    let older: Value = serde_json::from_str(&older).expect("CLI did not return valid JSON");

    assert_eq!(older["pagination"]["total"], 0, "{older}");

    let args = ["log", "activity", "--entity", "unrecognised"];

    let refused = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(&args, &refused, "unknown activity entity");

    let args = ["log", "activity", "--since", "yesterday"];

    let refused = app.run_cli(&args, None).await;

    assert!(!refused.status.success());
}

/// Verify that `log access` reads the access log the daemon saved and refuses an unknown result.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn log_access_lists_api_requests() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-access.example");
    let path = format!("/zones/{zone_name}");

    let (status, _) = app.send_request(Method::GET, &path, None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);

    // The writer saves after the answer, so wait for the row before the CLI reads it.
    app.wait_for_access_log("result=failed", |log| log["target"] == path)
        .await;

    let listed = app
        .run_cli_success(
            &[
                "log", "access", "--source", "api", "--result", "failed", "--output", "json",
            ],
            None,
        )
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");

    assert!(
        listed["items"]
            .as_array()
            .expect("log list has items")
            .iter()
            .any(|log| log["target"] == path && log["response_code"] == "404"),
        "{listed}"
    );

    let table = app
        .run_cli_success(&["log", "access", "--result", "failed"], None)
        .await;

    assert!(table.contains(&format!("GET {path}")), "{table}");

    let args = ["log", "access", "--result", "refused"];

    let refused = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(&args, &refused, "unsupported access result");
}
