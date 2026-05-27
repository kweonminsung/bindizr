use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use bindizr::{
    ApiRouter, config,
    database::{self, DatabasePool, model::zone::Zone},
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tower::ServiceExt;

pub(crate) struct TestContext {
    pub api_router: Router,
    pub db_pool: SqlitePool,
}

impl TestContext {
    pub(crate) async fn new() -> Self {
        let config_path = "tests/fixture/bindizr.conf.toml";

        // Initialize components (skip if already initialized)
        config::initialize(Some(config_path));
        database::initialize().await;

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
        let api_router = ApiRouter::routes().await;

        Self {
            api_router,
            db_pool,
        }
    }

    pub(crate) async fn create_test_zone(&self) -> Zone {
        let zone = Zone {
            id: 0, // Will be set by database
            name: "example.com".to_string(),
            primary_ns: "ns1.example.com".to_string(),
            admin_email: "admin@example.com".to_string(),
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
            INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .bind(zone.created_at)
        .execute(&self.db_pool)
        .await
        .expect("Failed to insert test zone");

        let zone_id = result.last_insert_rowid() as i32;

        Zone {
            id: zone_id,
            ..zone
        }
    }

    pub(crate) async fn make_request(
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
