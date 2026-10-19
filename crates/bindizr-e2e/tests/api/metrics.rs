use reqwest::{Method, StatusCode};

use crate::common::TestApp;

/// Read one numeric sample from a Prometheus metrics response.
fn metric_value(text: &str, name: &str) -> f64 {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("metric {name} missing from scrape"))
}

/// Verify that `metrics` reports zone totals and database up.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn metrics_reports_zone_totals_and_database_up() {
    let app = TestApp::start().await;
    app.create_test_zone().await;

    let (status, body) = app.send_request(Method::GET, "/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    let text = body.as_str().expect("metrics body is prometheus text");
    assert!(text.contains("bindizr_build_info"));
    assert_eq!(metric_value(text, "bindizr_database_up"), 1.0);
    assert!(metric_value(text, "bindizr_zones_total") >= 1.0);
    assert!(metric_value(text, "bindizr_started_at_seconds") > 0.0);
}

/// Verify that `metrics` counts HTTP requests by route.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn metrics_counts_http_requests_by_route() {
    let app = TestApp::start().await;

    app.send_request(Method::GET, "/health", None).await;

    let (status, body) = app.send_request(Method::GET, "/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    let text = body.as_str().expect("metrics body is prometheus text");
    assert!(
        text.contains(r#"bindizr_http_requests_total{method="GET",route="/health",status="200"}"#)
    );
}

/// A later zone's failure rolls back the earlier zone and its success metric.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn serial_bumps_count_only_committed_versions() {
    use serde_json::json;

    use crate::common::TestAppOptions;

    let app = TestApp::start_with_options(TestAppOptions {
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let first = app.zone_name("a-metrics.example");
    let second = app.zone_name("z-metrics.example");
    app.create_zone_cli(&first, "3600").await;
    app.create_zone_cli(&second, "3600").await;
    let (_, before) = app.send_request(Method::GET, "/metrics", None).await;
    let before = metric_value(before.as_str().unwrap(), "bindizr_zone_serial_bumps_total");
    assert_eq!(before, 2.0);
    let serial = app.read_zone_serial(&first).await;
    let (status, body) = app
        .send_request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [
                    {"name": format!("ok.{first}"), "type": "A", "values": ["192.0.2.1"]},
                    {"name": format!("bad.{second}"), "type": "A", "values": ["192.0.2.1"]},
                    {"name": format!("bad.{second}"), "type": "CNAME", "values": ["target.example.net."]}
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(app.read_zone_serial(&first).await, serial);
    let import_path = format!("/zones/{}/import", app.zone_name("preview-metrics.example"));
    let content = concat!(
        "@ IN SOA ns.example.net. admin.example.net. 42 300 60 86400 300\n",
        "@ IN NS ns.example.net.\n",
        "www IN A 192.0.2.1\n",
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &import_path,
            Some(json!({"create": true, "dry_run": true, "content": content})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], false);
    let (_, after) = app.send_request(Method::GET, "/metrics", None).await;
    assert_eq!(
        metric_value(after.as_str().unwrap(), "bindizr_zone_serial_bumps_total"),
        before
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [
                    {"name": format!("ok.{first}"), "type": "A", "values": ["192.0.2.1"]},
                    {"name": format!("ok.{second}"), "type": "A", "values": ["192.0.2.1"]}
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, after) = app.send_request(Method::GET, "/metrics", None).await;
    assert_eq!(
        metric_value(after.as_str().unwrap(), "bindizr_zone_serial_bumps_total"),
        before + 2.0
    );
    let (status, body) = app
        .send_request(
            Method::POST,
            &import_path,
            Some(json!({"create": true, "content": content})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true);
    let (_, after) = app.send_request(Method::GET, "/metrics", None).await;
    assert_eq!(
        metric_value(after.as_str().unwrap(), "bindizr_zone_serial_bumps_total"),
        before + 4.0
    );
}
