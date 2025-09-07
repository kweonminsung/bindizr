use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use bindizr::{
    api::controller::ApiController,
    config,
    database::{
        self, DatabasePool,
        model::{
            record::{Record, RecordType},
            zone::Zone,
        },
    },
    serializer,
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tower::ServiceExt;

pub struct TestContext {
    pub api_router: Router,
    pub db_pool: SqlitePool,
}

impl TestContext {
    pub async fn new() -> Self {
        let config_path = "tests/fixture/bindizr.conf.toml";

        // Initialize components (skip if already initialized)
        config::initialize(Some(config_path));
        database::initialize().await;
        serializer::initialize();

        // Get database pool
        let db_pool = match database::get_pool() {
            DatabasePool::SQLite(pool) => pool.clone(),
            _ => panic!("Expected SQLite pool for tests"),
        };

        // Clear the database for a clean test environment
        sqlx::query("DELETE FROM records")
            .execute(&db_pool)
            .await
            .expect("Failed to clear records table");
        sqlx::query("DELETE FROM zones")
            .execute(&db_pool)
            .await
            .expect("Failed to clear zones table");

        // Create API router
        let api_router = ApiController::routes().await;

        Self {
            api_router,
            db_pool,
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
            created_at: chrono::Utc::now(),
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
            created_at: chrono::Utc::now(),
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

        let response = self.api_router.clone().oneshot(request).await.unwrap();
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
