use serde_json::Value;

use crate::common::TestApp;

/// Verify that the CLI notifies all enabled zones or one named zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_supports_all_zones_and_one_zone() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("cli-notify.example");

    app.create_zone_cli(&zone_name, "3600").await;

    // No zone name means all enabled zones.
    let all = app.run_cli_success(&["zone", "notify"], None).await;

    assert!(
        all.contains("NOTIFY sent successfully for all enabled zones"),
        "{all}"
    );

    let one = app
        .run_cli_success(&["zone", "notify", &zone_name, "--bump-serial"], None)
        .await;

    assert!(
        one.contains(&format!(
            "NOTIFY sent successfully for zone: {zone_name} (serial bumped)"
        )),
        "{one}"
    );

    let notified = app
        .run_cli_success(
            &[
                "zone",
                "notify",
                "catalog.bindizr",
                "--bump-serial",
                "--output",
                "json",
            ],
            None,
        )
        .await;
    let notified: Value = serde_json::from_str(&notified).expect("CLI did not return valid JSON");

    assert_eq!(
        notified["message"],
        "NOTIFY sent successfully for zone: catalog.bindizr"
    );
}
