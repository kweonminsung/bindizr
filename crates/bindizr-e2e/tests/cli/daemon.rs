use crate::common::TestApp;

// Local mode only: in compose the daemon is the container's PID 1, so
// stopping it would recycle the shared stack under the remaining tests.

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn restart_reexecs_daemon_in_place() {
    let app = TestApp::start().await;
    if app.has_dns_secondaries() {
        return;
    }

    let output = app.run_cli_success(&["restart"]).await;
    assert!(output.contains("Bindizr restarted"));

    let status = app.run_cli_success(&["status"]).await;
    assert!(status.contains("Running"));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn stop_shuts_down_daemon() {
    let app = TestApp::start().await;
    if app.has_dns_secondaries() {
        return;
    }

    let output = app.run_cli_success(&["stop"]).await;
    assert!(output.contains("Bindizr stopped"));

    let args = ["status"];
    let after = app.run_cli(&args).await;
    assert!(!after.status.success());
}
