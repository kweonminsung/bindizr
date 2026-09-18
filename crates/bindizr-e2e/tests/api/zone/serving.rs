use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions, probe_zone_soa};

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
    assert_eq!(body["zone"], zone_name);
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
                .all(|s| s["status"] == "in_sync");
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

/// Verify that a disabled zone stops answering DNS while remaining editable through the API.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_disabled_zone_leaves_the_dns_plane_but_stays_editable() {
    // The transfer ACL must admit the test's own loopback AXFR.
    let app = TestApp::start_with_options(TestAppOptions {
        secondary_addrs: "127.0.0.1".to_string(),
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let server = format!("127.0.0.1:{}", app.dns_port());
    assert!(
        probe_zone_soa(app.dns_port(), zone_name),
        "a served zone answers its SOA"
    );

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "enabled": false, "description": "paused for migration" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["zone"]["enabled"], false, "{body}");
    assert_eq!(
        body["zone"]["description"], "paused for migration",
        "{body}"
    );

    // Unknown to the DNS plane, so a secondary drops the zone instead of
    // serving a copy nothing refreshes.
    assert!(
        !probe_zone_soa(app.dns_port(), zone_name),
        "a disabled zone must not answer its SOA"
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "from_server": server, "mode": "replace" })),
        )
        .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a disabled zone must refuse the transfer: {body}"
    );

    // The management plane still holds it: listable under the filter, and
    // editable.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones?enabled=false&search={zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|zone| zone["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [zone_name], "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www", "type": "A", "value": "192.0.2.31",
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "enabled": true, "description": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["zone"]["description"].is_null(), "{body}");
    assert!(
        probe_zone_soa(app.dns_port(), zone_name),
        "re-enabling serves the zone again"
    );
}
