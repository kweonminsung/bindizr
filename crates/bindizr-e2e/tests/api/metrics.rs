use reqwest::{Method, StatusCode};

use crate::common::TestApp;

fn metric_value(text: &str, name: &str) -> f64 {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("metric {name} missing from scrape"))
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn metrics_reports_zone_totals_and_database_up() {
    let app = TestApp::start().await;
    app.create_test_zone().await;

    let (status, body) = app.request(Method::GET, "/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    let text = body.as_str().expect("metrics body is prometheus text");
    assert!(text.contains("bindizr_build_info"));
    assert_eq!(metric_value(text, "bindizr_database_up"), 1.0);
    assert!(metric_value(text, "bindizr_zones_total") >= 1.0);
    assert!(metric_value(text, "bindizr_started_at_seconds") > 0.0);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn metrics_counts_http_requests_by_route() {
    let app = TestApp::start().await;

    app.request(Method::GET, "/health", None).await;

    let (status, body) = app.request(Method::GET, "/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    let text = body.as_str().expect("metrics body is prometheus text");
    assert!(
        text.contains(r#"bindizr_http_requests_total{method="GET",route="/health",status="200"}"#)
    );
}
