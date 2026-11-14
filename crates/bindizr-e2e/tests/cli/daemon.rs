//! Local daemon lifecycle checks: stopping the container's PID 1 in Compose
//! mode would recycle the shared stack beneath the remaining tests.

use crate::common::TestApp;

/// Verify that `status` reports running daemon.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn status_reports_running_daemon() {
    let app = TestApp::start().await;

    let status = app.run_cli_success(&["status"], None).await;

    assert!(status.contains("BINDIZR STATUS"));
    assert!(status.contains("Running"));
    assert!(status.contains("Uptime:"), "{status}");
    assert!(status.contains("API: http://"), "{status}");
    assert!(status.contains("zones)"), "{status}");
}

/// Verify that restart reexecs daemon in place.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn restart_reexecs_daemon_in_place() {
    let app = TestApp::start().await;

    if app.has_dns_secondaries() {
        return;
    }

    let restarted = app.run_cli_success(&["restart"], None).await;

    assert!(restarted.contains("Bindizr restarted"));

    let status = app.run_cli_success(&["status"], None).await;

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

    let stopped = app.run_cli_success(&["stop"], None).await;

    assert!(stopped.contains("Bindizr stopped"));

    let args = ["status"];

    let refused = app.run_cli(&args, None).await;

    assert!(!refused.status.success());
}
