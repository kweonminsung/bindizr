use reqwest::{Method, StatusCode};

use crate::common::{TestApp, TestAppOptions};

fn openapi_options() -> TestAppOptions {
    TestAppOptions {
        openapi_enabled: true,
        ..TestAppOptions::default()
    }
}

// Unauthenticated and describing every endpoint, so it stays off by default.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_is_absent_unless_enabled() {
    let app = TestApp::start_with_options(TestAppOptions::default()).await;

    for path in ["/openapi.json", "/openapi.yaml"] {
        let (status, _) = app.request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_is_served_when_enabled() {
    let app = TestApp::start_with_options(openapi_options()).await;

    let (status, body) = app.request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["paths"]["/zones"]["get"].is_object());

    // YAML is not JSON, so the harness hands it back as a plain string.
    let (status, body) = app.request(Method::GET, "/openapi.yaml", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.as_str().is_some_and(|yaml| yaml.contains("openapi:")),
        "YAML document was not served"
    );
}

// The document is the API's own description, so it sits outside the auth layer.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_needs_no_token() {
    let app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        ..openapi_options()
    })
    .await;

    let (status, _) = app.request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
}
