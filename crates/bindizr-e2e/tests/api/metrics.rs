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
