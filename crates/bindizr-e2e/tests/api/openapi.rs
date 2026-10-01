use reqwest::{Method, StatusCode};

use crate::common::{TestApp, TestAppOptions};

/// Verify that the unauthenticated API description is disabled by default.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_document_is_absent_unless_enabled() {
    let app = TestApp::start_local().await;

    for path in ["/openapi.json", "/openapi.yaml"] {
        let (status, _) = app.send_request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// Verify that enabled JSON and YAML API descriptions need no token.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn openapi_documents_need_no_token_when_enabled() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
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

/// Keep documented page limits aligned with the API's accepted query values.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn pagination_limits_match_the_openapi_contract() {
    let app = TestApp::start_with_options(TestAppOptions {
        openapi_enabled: true,
        ..Default::default()
    })
    .await;

    let (status, document) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    for (path, item) in document["paths"].as_object().unwrap() {
        let Some(parameters) = item["get"]["parameters"].as_array() else {
            continue;
        };
        for parameter in parameters {
            if parameter["name"] == "limit" && parameter["in"] == "query" {
                assert_eq!(parameter["schema"]["minimum"], 1, "{path}");
                assert_eq!(parameter["schema"]["maximum"], 1000, "{path}");
            }
        }
    }

    for path in ["/zones", "/tokens"] {
        let (status, body) = app.send_request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert_eq!(body["pagination"]["limit"], 50, "{path}");

        for (limit, expected_status) in [
            (0, StatusCode::BAD_REQUEST),
            (1, StatusCode::OK),
            (1000, StatusCode::OK),
            (1001, StatusCode::BAD_REQUEST),
        ] {
            let url = format!("{path}?limit={limit}");
            let (status, body) = app.send_request(Method::GET, &url, None).await;
            assert_eq!(status, expected_status, "{url}: {body}");
            if status == StatusCode::OK {
                assert_eq!(body["pagination"]["limit"], limit, "{url}");
            } else {
                assert_eq!(body["code"], "INVALID_INPUT", "{url}: {body}");
            }
        }
    }
}
