use reqwest::{Method, StatusCode};

use crate::common::{TestApp, TestAppOptions};

/// Verify that health reports healthy with database available.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn health_reports_healthy_with_database_available() {
    let app = TestApp::start().await;

    let (status, body) = app.send_request(Method::GET, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

/// Verify that home reports running message.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn home_reports_running_message() {
    let app = TestApp::start().await;

    let (status, body) = app.send_request(Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "bindizr API running");
}

/// Verify that the API serves over TLS and nothing over plain HTTP.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn the_api_serves_over_tls_and_nothing_over_plain_http() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        tls: true,
        ..Default::default()
    })
    .await;

    // The harness reached the daemon over https to get here, certificate
    // verified against the pair generated for this run.
    let (status, body) = app.send_request(Method::GET, "/health", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "healthy", "{body}");

    // A bearer token must not have a plaintext path to the same port.
    let plain = reqwest::Client::new()
        .get(app.base_url().replace("https://", "http://") + "/health")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;
    assert!(plain.is_err(), "plain HTTP answered: {plain:?}");

    // An untrusted client is refused rather than downgraded.
    let untrusted = reqwest::Client::new()
        .get(format!("{}/health", app.base_url()))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;
    assert!(
        untrusted.is_err(),
        "untrusted client accepted: {untrusted:?}"
    );
}
