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
use tempfile::NamedTempFile;
use tower::ServiceExt;

pub struct TestContext {
    pub app: Router,
    pub db_pool: SqlitePool,
    pub _temp_db_file: NamedTempFile, // Keep alive for test duration
    pub _temp_config_file: NamedTempFile, // Keep alive for test duration
}

impl TestContext {
    pub async fn new() -> Self {
        // Create temporary SQLite database
        let temp_db_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_db_file.path().to_str().unwrap();

        // Create temporary configuration file
        let temp_config_file = NamedTempFile::new().expect("Failed to create temp config file");
        let config_path = temp_config_file.path().to_str().unwrap();

        // Write default configuration to temp file
        std::fs::write(
            config_path,
            format!(
                r#"
            [api]
            host = "127.0.0.1"
            port = 3000
            require_authentication = false

            [database]
            type = "sqlite"

            [database.mysql]
            server_url = ""

            [database.sqlite]
            file_path = "{}"

            [database.postgresql]
            server_url = ""

            [bind]
            bind_config_path = "/etc/bind"
            rndc_server_url = "127.0.0.1:953"
            rndc_algorithm = "sha256"
            rndc_secret_key = "YmluZGl6cg==" # This is "test" base64-encoded

            [logging]
            log_level = "debug"
            enable_file_logging = false
            log_file_path = "/var/log/bindizr"
            "#,
                db_path
            ),
        )
        .unwrap();

        // Initialize components (skip if already initialized)
        config::initialize(Some(config_path));
        database::initialize().await;
        serializer::initialize();

        // Get database pool
        let db_pool = match database::get_pool() {
            DatabasePool::SQLite(pool) => pool.clone(),
            _ => panic!("Expected SQLite pool for tests"),
        };

        // Create API router
        let app = ApiController::routes().await;

        Self {
            app,
            db_pool,
            _temp_db_file: temp_db_file,
            _temp_config_file: temp_config_file,
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
