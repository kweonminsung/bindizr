use crate::common::{TestApp, assert_cli_failure_contains};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_all_zones_and_one_zone() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-notify.example");
    app.create_zone_cli(&zone_name, "3600").await;

    let all = app.run_cli_success(&["notify"]).await;
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

    // The zone form names its zone; every zone is the top-level command.
    let args = ["zone", "notify"];
    let refused = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &refused, "ZONE_NAME");
}
