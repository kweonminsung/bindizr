use reqwest::{Method, StatusCode};

use crate::common::{TestApp, TestAppOptions};

/// Verify that the OpenAPI document is disabled by default.
///
/// It describes every endpoint and is served without authentication when enabled.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_is_absent_unless_enabled() {
    let app = TestApp::start_local().await;

    for path in ["/openapi.json", "/openapi.yaml"] {
        let (status, _) = app.send_request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// Verify that openapi document is served when enabled.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_is_served_when_enabled() {
    let app = TestApp::start_with_options(TestAppOptions {
        openapi_enabled: true,
        ..Default::default()
    })
    .await;

    let (status, body) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["paths"]["/zones"]["get"].is_object());

    // YAML is not JSON, so the harness hands it back as a plain string.
    let (status, body) = app.send_request(Method::GET, "/openapi.yaml", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.as_str().is_some_and(|yaml| yaml.contains("openapi:")),
        "YAML document was not served"
    );
}

/// Verify that the API description remains accessible without a token outside the
/// authentication layer.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_needs_no_token() {
    let app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        openapi_enabled: true,
        ..Default::default()
    })
    .await;

    let (status, _) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
}
