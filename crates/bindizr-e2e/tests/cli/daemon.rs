//! Local daemon lifecycle checks: stopping the container's PID 1 in Compose
//! mode would recycle the shared stack beneath the remaining tests.

use crate::common::TestApp;

/// Verify that `status` reports running daemon.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn status_reports_running_daemon() {
    let app = TestApp::start().await;

    let status = app.run_cli_success(&["status"]).await;
    assert!(status.contains("BINDIZR STATUS"));
    assert!(status.contains("Running"));
}

/// Verify that restart reexecs daemon in place.
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

/// Verify that stop shuts down daemon.
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
