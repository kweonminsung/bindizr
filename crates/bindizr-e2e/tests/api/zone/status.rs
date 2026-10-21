use reqwest::{Method, StatusCode};

use crate::common::TestApp;

/// Verify that `zone_status` reports secondaries.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_status_reports_secondaries() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone_name"], zone_name);
    assert_eq!(
        body["serial"].as_i64().unwrap(),
        zone["serial"].as_i64().unwrap()
    );

    let secondaries = body["secondaries"].as_array().expect("missing secondaries");

    if app.has_dns_secondaries() {
        // Compose mode: both BIND9 secondaries must converge to in_sync.
        assert_eq!(secondaries.len(), 2);
        let mut attempts = 0;

        loop {
            let (_, body) = app
                .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
                .await;
            let all_in_sync = body["secondaries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|secondary| secondary["status"] == "in_sync");

            if all_in_sync {
                break;
            }

            attempts += 1;

            assert!(attempts < 60, "secondaries never reached in_sync: {body}");

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    } else {
        // Local mode has no secondaries configured.
        assert!(secondaries.is_empty());
    }

    let missing_zone = app.zone_name("missing.example");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{missing_zone}/status"), None)
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
}
