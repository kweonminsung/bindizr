use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::common;
use crate::common::TestApp;

/// Verify that `log audit` shows socket changes without an actor and
/// narrows by entity and name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn log_audit_shows_socket_changes() {
    let app = TestApp::start().await;
    let name = format!("{}-cli-audited", app.namespace());

    app.run_cli_success(&["role", "create", &name], None).await;
    app.run_cli_success(&["token", "create", &name, "--role", &name], None)
        .await;
    app.run_cli_success(&["token", "delete", &name], None).await;

    let listed = app
        .run_cli_success(
            &[
                "log", "audit", "--entity", "token", "--name", &name, "--output", "json",
            ],
            None,
        )
        .await;
    let listed: Value = serde_json::from_str(&listed).expect("CLI did not return valid JSON");

    assert_eq!(listed["pagination"]["total"], 2, "{listed}");
    let items = listed["items"].as_array().unwrap();

    assert_eq!(items[0]["operation"], "delete");
    assert_eq!(items[1]["operation"], "create");

    for log in items {
        assert_eq!(log["entity"], "token");
        assert_eq!(log["entity_name"], name);
        // A socket command is the daemon's own user: no token names it.
        assert_eq!(log["change_source"], "socket");
        assert!(log["changed_by"].is_null(), "{log}");
    }

    // Without an entity, the role's own creation is listed beside its token's;
    // DETAIL says what each set.
    let table = app
        .run_cli_success(&["log", "audit", "--name", &name], None)
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

    // Sorted by entity, oldest first within the role's changes.
    let sorted = app
        .run_cli_success(
            &[
                "log", "audit", "--name", &name, "--sort", "entity", "--order", "asc", "--output",
                "json",
            ],
            None,
        )
        .await;
    let sorted: Value = serde_json::from_str(&sorted).expect("CLI did not return valid JSON");
    let entities: Vec<&str> = sorted["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|log| log["entity"].as_str().unwrap())
        .collect();

    assert_eq!(entities, ["role", "token", "token"], "{sorted}");

    // A span ago reaches the daemon as a time: everything is newer than an
    // hour ago, and nothing is older.
    let recent = app
        .run_cli_success(
            &[
                "log", "audit", "--name", &name, "--since", "1h", "--output", "json",
            ],
            None,
        )
        .await;
    let recent: Value = serde_json::from_str(&recent).expect("CLI did not return valid JSON");

    assert_eq!(recent["pagination"]["total"], 3, "{recent}");

    let older = app
        .run_cli_success(
            &[
                "log", "audit", "--name", &name, "--until", "1h", "--output", "json",
            ],
            None,
        )
        .await;
    let older: Value = serde_json::from_str(&older).expect("CLI did not return valid JSON");

    assert_eq!(older["pagination"]["total"], 0, "{older}");

    let args = ["log", "audit", "--entity", "record"];

    let refused = app.run_cli(&args, None).await;
    common::assert_cli_failure_contains(&args, &refused, "unsupported audit entity");

    let args = ["log", "audit", "--since", "yesterday"];

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
            .unwrap()
            .iter()
            .any(|log| log["target"] == path && log["status"] == "404"),
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
