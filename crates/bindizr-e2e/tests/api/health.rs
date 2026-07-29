use reqwest::{Method, StatusCode};

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn health_reports_healthy_with_database_available() {
    let app = TestApp::start().await;

    let (status, body) = app.request(Method::GET, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn home_reports_running_message() {
    let app = TestApp::start().await;

    let (status, body) = app.request(Method::GET, "/", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "bindizr API running");
}
