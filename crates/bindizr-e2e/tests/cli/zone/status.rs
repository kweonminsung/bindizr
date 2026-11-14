use crate::common::TestApp;

/// Verify that the CLI reports zone status.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_status_returns_current_serial_via_cli() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("status.example");

    app.create_zone_cli(&zone_name, "3600").await;

    let status = app
        .run_cli_success(&["zone", "status", &zone_name], None)
        .await;

    // Serial 1: the zone and its apex NS arrive in one version.
    assert!(status.contains(&format!("Zone {zone_name} (serial 1)")));

    if !app.has_dns_secondaries() {
        assert!(status.contains("No enabled secondaries."));
    }
}
