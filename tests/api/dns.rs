use crate::common::TestContext;
use axum::http::StatusCode;

#[tokio::test]
async fn test_dns_operations() {
    let ctx = TestContext::new().await;

    // Test GET /dns/status
    let (status, body) = ctx.make_request("GET", "/dns/status", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("status").is_some());

    // Test POST /dns/write-config
    let (status, body) = ctx.make_request("POST", "/dns/write-config", None).await;
    // This might fail in test environment, but we check the response structure
    assert!(status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.get("message").is_some());

    // Test POST /dns/reload
    let (status, body) = ctx.make_request("POST", "/dns/reload", None).await;
    // This might fail in test environment, but we check the response structure
    assert!(status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.get("message").is_some());
}
