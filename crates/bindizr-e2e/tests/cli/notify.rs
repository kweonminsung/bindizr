use crate::common::TestApp;

/// Verify CLI notification of all zones or one named zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_all_zones_and_one_zone() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-notify.example");
    app.create_zone_cli(&zone_name, "3600").await;

    // No zone name means every zone.
    let all = app.run_cli_success(&["zone", "notify"]).await;
    assert!(
        all.contains("NOTIFY sent successfully for all zones"),
        "{all}"
    );

    let one = app
        .run_cli_success(&["zone", "notify", &zone_name, "--bump-serial"])
        .await;
    assert!(
        one.contains(&format!(
            "NOTIFY sent successfully for zone: {zone_name} (serial bumped)"
        )),
        "{one}"
    );
}
