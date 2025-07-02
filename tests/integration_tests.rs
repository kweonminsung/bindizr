use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use bindizr::{
    api::controller::ApiController,
    config,
    database::{
        self,
        model::{
            record::{Record, RecordType},
            zone::Zone,
        },
    },
    logger, serializer,
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::env;
use tempfile::NamedTempFile;
use tower::ServiceExt;

pub struct TestContext {
    pub app: Router,
    pub db_pool: SqlitePool,
    pub _temp_file: NamedTempFile, // Keep alive for test duration
}

impl TestContext {
    pub async fn new() -> Self {
        // Create temporary SQLite database
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path().to_str().unwrap();

        // Set environment variables for test configuration
        env::set_var("DATABASE_URL", format!("sqlite://{}", db_path));
        env::set_var("DATABASE_TYPE", "sqlite");
        env::set_var("API_HOST", "127.0.0.1");
        env::set_var("API_PORT", "3000");
        env::set_var("API_REQUIRE_AUTHENTICATION", "false");
        env::set_var("LOG_LEVEL", "debug");
        env::set_var("LOG_TO_FILE", "false");

        // Initialize components
        config::initialize();
        logger::initialize(false);
        database::initialize().await;
        serializer::initialize();

        // Get database pool
        let db_pool = database::get_pool().clone();

        // Create API router
        let app = ApiController::routes().await;

        Self {
            app,
            db_pool,
            _temp_file: temp_file,
        }
    }

    pub async fn create_test_zone(&self) -> Zone {
        let zone = Zone {
            id: 0, // Will be set by database
            name: "example.com".to_string(),
            primary_ns: "ns1.example.com".to_string(),
            primary_ns_ip: "192.168.1.1".to_string(),
            admin_email: "admin.example.com".to_string(),
            ttl: 3600,
            serial: 2023010101,
            refresh: 7200,
            retry: 3600,
            expire: 604800,
            minimum_ttl: 86400,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, primary_ns_ip, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.primary_ns_ip)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .bind(&zone.created_at)
        .execute(&self.db_pool)
        .await
        .expect("Failed to insert test zone");

        Zone {
            id: result.last_insert_rowid() as i32,
            ..zone
        }
    }

    pub async fn create_test_record(&self, zone_id: i32) -> Record {
        let record = Record {
            id: 0, // Will be set by database
            name: "www.example.com".to_string(),
            record_type: RecordType::A,
            value: "192.168.1.100".to_string(),
            ttl: Some(3600),
            priority: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            zone_id,
        };

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, created_at, zone_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(&record.created_at)
        .bind(record.zone_id)
        .execute(&self.db_pool)
        .await
        .expect("Failed to insert test record");

        Record {
            id: result.last_insert_rowid() as i32,
            ..record
        }
    }

    pub async fn make_request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request_builder = Request::builder().method(method).uri(path);

        if body.is_some() {
            request_builder = request_builder.header("content-type", "application/json");
        }

        let request = if let Some(body) = body {
            request_builder.body(Body::from(body.to_string())).unwrap()
        } else {
            request_builder.body(Body::empty()).unwrap()
        };

        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        let json: Value = if body.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(&body).unwrap_or_else(|_| json!(String::from_utf8_lossy(&body)))
        };

        (status, json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_home() {
        let ctx = TestContext::new().await;

        let (status, body) = ctx.make_request("GET", "/", None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["msg"], "bindizr API running");
    }

    #[tokio::test]
    async fn test_zone_crud_operations() {
        let ctx = TestContext::new().await;

        // Test GET /zones (empty)
        let (status, body) = ctx.make_request("GET", "/zones", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.as_array().unwrap().is_empty());

        // Test POST /zones (create)
        let create_zone_request = json!({
            "name": "test.com",
            "primary_ns": "ns1.test.com",
            "primary_ns_ip": "10.0.0.1",
            "admin_email": "admin.test.com",
            "ttl": 3600,
            "serial": 2023010101,
            "refresh": 7200,
            "retry": 3600,
            "expire": 604800,
            "minimum_ttl": 86400
        });

        let (status, body) = ctx
            .make_request("POST", "/zones", Some(create_zone_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let zone_id = body["data"]["id"].as_i64().unwrap();
        assert_eq!(body["data"]["name"], "test.com");

        // Test GET /zones/{id}
        let (status, body) = ctx
            .make_request("GET", &format!("/zones/{}", zone_id), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["name"], "test.com");

        // Test GET /zones (with data)
        let (status, body) = ctx.make_request("GET", "/zones", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 1);

        // Test PUT /zones/{id} (update)
        let update_zone_request = json!({
            "name": "updated-test.com",
            "primary_ns": "ns1.updated-test.com",
            "primary_ns_ip": "10.0.0.2",
            "admin_email": "admin.updated-test.com",
            "ttl": 7200,
            "serial": 2023010102,
            "refresh": 14400,
            "retry": 7200,
            "expire": 1209600,
            "minimum_ttl": 172800
        });

        let (status, body) = ctx
            .make_request(
                "PUT",
                &format!("/zones/{}", zone_id),
                Some(update_zone_request),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["name"], "updated-test.com");

        // Test DELETE /zones/{id}
        let (status, _) = ctx
            .make_request("DELETE", &format!("/zones/{}", zone_id), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Verify deletion
        let (status, _) = ctx
            .make_request("GET", &format!("/zones/{}", zone_id), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_record_crud_operations() {
        let ctx = TestContext::new().await;
        let zone = ctx.create_test_zone().await;

        // Test GET /records (empty)
        let (status, body) = ctx
            .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.as_array().unwrap().is_empty());

        // Test POST /records (create)
        let create_record_request = json!({
            "name": "api.example.com",
            "record_type": "A",
            "value": "192.168.1.200",
            "ttl": 1800,
            "zone_id": zone.id
        });

        let (status, body) = ctx
            .make_request("POST", "/records", Some(create_record_request))
            .await;
        assert_eq!(status, StatusCode::CREATED);

        let record_id = body["data"]["id"].as_i64().unwrap();
        assert_eq!(body["data"]["name"], "api.example.com");
        assert_eq!(body["data"]["record_type"], "A");

        // Test GET /records/{id}
        let (status, body) = ctx
            .make_request("GET", &format!("/records/{}", record_id), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["name"], "api.example.com");

        // Test GET /records (with data)
        let (status, body) = ctx
            .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 1);

        // Test PUT /records/{id} (update)
        let update_record_request = json!({
            "name": "api-updated.example.com",
            "record_type": "A",
            "value": "192.168.1.201",
            "ttl": 3600,
            "zone_id": zone.id
        });

        let (status, body) = ctx
            .make_request(
                "PUT",
                &format!("/records/{}", record_id),
                Some(update_record_request),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["name"], "api-updated.example.com");
        assert_eq!(body["data"]["value"], "192.168.1.201");

        // Test DELETE /records/{id}
        let (status, _) = ctx
            .make_request("DELETE", &format!("/records/{}", record_id), None)
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Verify deletion
        let (status, _) = ctx
            .make_request("GET", &format!("/records/{}", record_id), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_zone_rendered_output() {
        let ctx = TestContext::new().await;
        let zone = ctx.create_test_zone().await;
        let _record = ctx.create_test_record(zone.id).await;

        // Test GET /zones/{id}/rendered
        let (status, body) = ctx
            .make_request("GET", &format!("/zones/{}/rendered", zone.id), None)
            .await;
        assert_eq!(status, StatusCode::OK);

        // Should return rendered zone file content
        let content = body.as_str().unwrap();
        assert!(content.contains("example.com"));
        assert!(content.contains("SOA"));
        assert!(content.contains("NS"));
        assert!(content.contains("www.example.com"));
    }

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

    #[tokio::test]
    async fn test_error_handling() {
        let ctx = TestContext::new().await;

        // Test 404 for non-existent zone
        let (status, _) = ctx.make_request("GET", "/zones/99999", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Test 404 for non-existent record
        let (status, _) = ctx.make_request("GET", "/records/99999", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Test invalid JSON for zone creation
        let invalid_json = json!({
            "name": "test.com"
            // Missing required fields
        });

        let (status, _) = ctx.make_request("POST", "/zones", Some(invalid_json)).await;
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY);

        // Test invalid record type
        let zone = ctx.create_test_zone().await;
        let invalid_record = json!({
            "name": "test.example.com",
            "record_type": "INVALID",
            "value": "192.168.1.1",
            "zone_id": zone.id
        });

        let (status, _) = ctx
            .make_request("POST", "/records", Some(invalid_record))
            .await;
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_zone_history() {
        let ctx = TestContext::new().await;
        let zone = ctx.create_test_zone().await;

        // Test GET /zones/{id}/history
        let (status, body) = ctx
            .make_request("GET", &format!("/zones/{}/history", zone.id), None)
            .await;
        assert_eq!(status, StatusCode::OK);

        // Should return history array (might be empty initially)
        assert!(body.as_array().is_some());
    }

    #[tokio::test]
    async fn test_record_history() {
        let ctx = TestContext::new().await;
        let zone = ctx.create_test_zone().await;
        let record = ctx.create_test_record(zone.id).await;

        // Test GET /records/{id}/history
        let (status, body) = ctx
            .make_request("GET", &format!("/records/{}/history", record.id), None)
            .await;
        assert_eq!(status, StatusCode::OK);

        // Should return history array (might be empty initially)
        assert!(body.as_array().is_some());
    }

    #[tokio::test]
    async fn test_multiple_record_types() {
        let ctx = TestContext::new().await;
        let zone = ctx.create_test_zone().await;

        let record_types = vec![
            ("mail.example.com", "MX", "10 mail.example.com", Some(10)),
            (
                "_sip._tcp.example.com",
                "SRV",
                "10 5 5060 sip.example.com",
                Some(10),
            ),
            (
                "example.com",
                "TXT",
                "v=spf1 include:_spf.google.com ~all",
                None,
            ),
            ("ipv6.example.com", "AAAA", "2001:db8::1", None),
            ("alias.example.com", "CNAME", "www.example.com", None),
        ];

        for (name, record_type, value, priority) in record_types {
            let create_request = json!({
                "name": name,
                "record_type": record_type,
                "value": value,
                "ttl": 3600,
                "priority": priority,
                "zone_id": zone.id
            });

            let (status, body) = ctx
                .make_request("POST", "/records", Some(create_request))
                .await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(body["data"]["record_type"], record_type);
            assert_eq!(body["data"]["value"], value);

            if let Some(expected_priority) = priority {
                assert_eq!(body["data"]["priority"], expected_priority);
            }
        }

        // Verify all records were created
        let (status, body) = ctx
            .make_request("GET", &format!("/records?zone_id={}", zone.id), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 5);
    }
}
