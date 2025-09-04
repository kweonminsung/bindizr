mod dns;
mod record;
mod zone;

mod test {
    use crate::common::TestContext;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_api_home() {
        let ctx = TestContext::new().await;

        let (status, body) = ctx.make_request("GET", "/", None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["msg"], "bindizr API running");
    }

    #[tokio::test]
    async fn test_error_handling() {
        let ctx = TestContext::new().await;

        // Test 400 for non-existent zone
        let (status, _) = ctx.make_request("GET", "/zones/99999", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Test 400 for non-existent record
        let (status, _) = ctx.make_request("GET", "/records/99999", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Test invalid JSON for zone creation
        let invalid_json = serde_json::json!({
            "name": "test.com"
            // Missing required fields
        });

        let (status, _) = ctx.make_request("POST", "/zones", Some(invalid_json)).await;
        assert!(status == StatusCode::BAD_REQUEST);

        // Test invalid record type
        let zone = ctx.create_test_zone().await;
        let invalid_record = serde_json::json!({
            "name": "test.example.com",
            "record_type": "INVALID",
            "value": "192.168.1.1",
            "zone_id": zone.id
        });

        let (status, _) = ctx
            .make_request("POST", "/records", Some(invalid_record))
            .await;
        assert!(status == StatusCode::BAD_REQUEST);
    }
}
