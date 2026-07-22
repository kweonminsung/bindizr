//! Database layer: connection-pool setup and repository implementations for
//! the MySQL, PostgreSQL, and SQLite backends.

use std::sync::OnceLock;

use sqlx::{
    MySql, Pool, Postgres, Sqlite, mysql::MySqlPoolOptions, postgres::PgPoolOptions,
    sqlite::SqlitePoolOptions,
};

pub mod error;
pub mod repository;
mod schema;
mod utils;

pub use bindizr_core::model;
pub(crate) use bindizr_core::{config, log_error, log_info};

static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();
static INITIALIZE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A connection pool for one of the supported database backends.
#[derive(Debug)]
pub enum DatabasePool {
    MySQL(Pool<MySql>),
    PostgreSQL(Pool<Postgres>),
    SQLite(Pool<Sqlite>),
}

/// Supported database backend types.
#[derive(Debug, Clone)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    SQLite,
}

/// Initialize the global database pool from configuration. Idempotent.
pub async fn initialize() {
    if is_initialized() {
        return;
    }

    let initialize_guard = INITIALIZE_LOCK.lock().await;

    if is_initialized() {
        return;
    }

    let bindizr_config = config::get_bindizr_config();

    let database_type = match bindizr_config.database.database_type {
        config::DatabaseType::Mysql => DatabaseType::MySQL,
        config::DatabaseType::Postgresql => DatabaseType::PostgreSQL,
        config::DatabaseType::Sqlite => DatabaseType::SQLite,
    };

    let database_url = match database_type {
        DatabaseType::MySQL => bindizr_config.database.mysql.server_url.clone(),
        DatabaseType::PostgreSQL => bindizr_config.database.postgresql.server_url.clone(),
        DatabaseType::SQLite => utils::to_sqlite_url(&bindizr_config.database.sqlite.file_path)
            .unwrap_or_else(|e| {
                log_error!("{}", e);
                std::process::exit(1);
            }),
    };

    let pool = match database_type {
        DatabaseType::MySQL => DatabasePool::new_mysql(&database_url).await,
        DatabaseType::PostgreSQL => DatabasePool::new_postgres(&database_url).await,
        DatabaseType::SQLite => DatabasePool::new_sqlite(&database_url).await,
    };

    if DATABASE_POOL.set(pool).is_err() {
        return;
    }

    drop(initialize_guard);
    log_info!("Database pool initialized");
}

fn is_initialized() -> bool {
    DATABASE_POOL.get().is_some()
}

/// Return the global database pool, panicking if not yet initialized.
pub fn get_pool() -> &'static DatabasePool {
    DATABASE_POOL.get().expect("Database pool not initialized")
}

/// Max pooled connections for the networked backends, scaled to the host.
/// sqlx's default is a flat 10; size it to the available parallelism instead.
fn networked_pool_max_connections() -> u32 {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    ((cores * 4) as u32).clamp(8, 64)
}

impl DatabasePool {
    /// Connect to MySQL, create tables, and return the pool.
    pub async fn new_mysql(url: &str) -> Self {
        let pool = MySqlPoolOptions::new()
            .max_connections(networked_pool_max_connections())
            .connect(url)
            .await
            .unwrap_or_else(|e| {
                log_error!("Failed to create MySQL database pool: {}", e);
                std::process::exit(1);
            });

        let database_pool = DatabasePool::MySQL(pool);

        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }

    /// Connect to PostgreSQL, create tables, and return the pool.
    pub async fn new_postgres(url: &str) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(networked_pool_max_connections())
            .connect(url)
            .await
            .unwrap_or_else(|e| {
                log_error!("Failed to create PostgreSQL database pool: {}", e);
                std::process::exit(1);
            });

        let database_pool = DatabasePool::PostgreSQL(pool);

        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }
    /// Connect to SQLite, create tables, and return the pool.
    pub async fn new_sqlite(url: &str) -> Self {
        let pool = SqlitePoolOptions::new()
            .after_connect(|conn, _| {
                Box::pin(async move {
                    // SQLite enforces foreign keys only when enabled per connection.
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect(url)
            .await
            .unwrap_or_else(|e| {
                log_error!("Failed to create SQLite database pool: {}", e);
                std::process::exit(1);
            });

        let database_pool = DatabasePool::SQLite(pool);

        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }

    async fn create_tables(&self) -> Result<(), String> {
        match self {
            DatabasePool::MySQL(pool) => {
                for query in schema::get_mysql_table_creation_queries() {
                    let mut conn = pool.acquire().await.map_err(|e| {
                        log_error!("Failed to acquire MySQL connection: {}", e);
                        e.to_string()
                    })?;
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log_error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
            }
            DatabasePool::PostgreSQL(pool) => {
                for query in schema::get_postgres_table_creation_queries() {
                    let mut conn = pool.acquire().await.map_err(|e| {
                        log_error!("Failed to acquire PostgreSQL connection: {}", e);
                        e.to_string()
                    })?;
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log_error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
            }
            DatabasePool::SQLite(pool) => {
                for query in schema::get_sqlite_table_creation_queries() {
                    let mut conn = pool.acquire().await.map_err(|e| {
                        log_error!("Failed to acquire SQLite connection: {}", e);
                        e.to_string()
                    })?;
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log_error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
            }
        }
        Ok(())
    }
}

/// Return a zone repository backed by the global pool.
pub fn get_zone_repository() -> Box<dyn repository::ZoneRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_repository(pool)
}

/// Return a record repository backed by the global pool.
pub fn get_record_repository() -> Box<dyn repository::RecordRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_record_repository(pool)
}

/// Return a TSIG key repository backed by the global pool.
pub fn get_tsig_key_repository() -> Box<dyn repository::TsigKeyRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_tsig_key_repository(pool)
}

/// Return a zone TSIG policy repository backed by the global pool.
pub fn get_zone_tsig_policy_repository() -> Box<dyn repository::ZoneTsigPolicyRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_tsig_policy_repository(pool)
}

/// Return an API token repository backed by the global pool.
pub fn get_api_token_repository() -> Box<dyn repository::ApiTokenRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_api_token_repository(pool)
}

/// Return a zone change repository backed by the global pool.
pub fn get_zone_change_repository() -> Box<dyn repository::ZoneChangeRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_change_repository(pool)
}

/// Return a zone snapshot repository backed by the global pool.
pub fn get_zone_snapshot_repository() -> Box<dyn repository::ZoneSnapshotRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_snapshot_repository(pool)
}

/// Return a catalog zone state repository backed by the global pool.
pub fn get_catalog_zone_state_repository() -> Box<dyn repository::CatalogZoneStateRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_catalog_zone_state_repository(pool)
}
