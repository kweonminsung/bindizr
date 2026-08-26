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
pub(crate) use bindizr_core::{config, log_error, log_info, log_warn};
use error::DatabaseError;

static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();
static INITIALIZE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A connection pool for one of the supported database backends.
#[derive(Debug)]
pub(crate) enum DatabasePool {
    MySQL(Pool<MySql>),
    PostgreSQL(Pool<Postgres>),
    SQLite(Pool<Sqlite>),
}

/// Supported database backend types.
#[derive(Debug, Clone)]
pub(crate) enum DatabaseType {
    MySQL,
    PostgreSQL,
    SQLite,
}

/// Initialize the global database pool from configuration. Idempotent.
pub async fn initialize() -> Result<(), DatabaseError> {
    if is_initialized() {
        return Ok(());
    }

    let initialize_guard = INITIALIZE_LOCK.lock().await;

    if is_initialized() {
        return Ok(());
    }

    let bindizr_config = config::bindizr_config();

    let database_type = match bindizr_config.database.database_type {
        config::DatabaseType::Mysql => DatabaseType::MySQL,
        config::DatabaseType::Postgresql => DatabaseType::PostgreSQL,
        config::DatabaseType::Sqlite => DatabaseType::SQLite,
    };

    let database_url = match database_type {
        DatabaseType::MySQL => bindizr_config.database.mysql.server_url.clone(),
        DatabaseType::PostgreSQL => bindizr_config.database.postgresql.server_url.clone(),
        DatabaseType::SQLite => utils::to_sqlite_url(&bindizr_config.database.sqlite.file_path)
            .map_err(DatabaseError::PoolError)?,
    };

    let pool = match database_type {
        DatabaseType::MySQL => DatabasePool::new_mysql(&database_url).await?,
        DatabaseType::PostgreSQL => DatabasePool::new_postgres(&database_url).await?,
        DatabaseType::SQLite => DatabasePool::new_sqlite(&database_url).await?,
    };

    // Cannot fail: the pool is set only here, under INITIALIZE_LOCK.
    DATABASE_POOL
        .set(pool)
        .expect("database pool initialized twice");

    drop(initialize_guard);
    log_info!("Database pool initialized");
    Ok(())
}

fn is_initialized() -> bool {
    DATABASE_POOL.get().is_some()
}

/// Return the global database pool, panicking if not yet initialized.
pub(crate) fn get_pool() -> &'static DatabasePool {
    DATABASE_POOL.get().expect("Database pool not initialized")
}

/// Max pooled connections, scaled to the host; sqlx's default is a flat 10.
/// SQLite shares it: under WAL the pool bounds read concurrency rather than
/// contending for the writer slot.
fn pool_max_connections() -> u32 {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    ((cores * 4) as u32).clamp(8, 64)
}

impl DatabasePool {
    /// Connect to MySQL, create tables, and return the pool.
    pub(crate) async fn new_mysql(url: &str) -> Result<Self, DatabaseError> {
        let pool = MySqlPoolOptions::new()
            .max_connections(pool_max_connections())
            .after_connect(|conn, _| {
                Box::pin(async move {
                    // Row locks, not version isolation, carry correctness:
                    // READ COMMITTED matches PostgreSQL and sheds gap locking.
                    sqlx::query("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        .execute(conn)
                        .await
                        .map(|_| ())
                })
            })
            .connect(url)
            .await
            .map_err(|e| {
                DatabaseError::PoolError(format!("Failed to create MySQL database pool: {}", e))
            })?;

        let database_pool = DatabasePool::MySQL(pool);
        database_pool
            .create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        Ok(database_pool)
    }

    /// Connect to PostgreSQL, create tables, and return the pool.
    pub(crate) async fn new_postgres(url: &str) -> Result<Self, DatabaseError> {
        let pool = PgPoolOptions::new()
            .max_connections(pool_max_connections())
            .after_connect(|conn, _| {
                Box::pin(async move {
                    // Already the default; pinned so all backends state one contract.
                    sqlx::query(
                        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED",
                    )
                    .execute(conn)
                    .await
                    .map(|_| ())
                })
            })
            .connect(url)
            .await
            .map_err(|e| {
                DatabaseError::PoolError(format!(
                    "Failed to create PostgreSQL database pool: {}",
                    e
                ))
            })?;

        let database_pool = DatabasePool::PostgreSQL(pool);
        database_pool
            .create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        Ok(database_pool)
    }
    /// Connect to SQLite, create tables, and return the pool.
    pub(crate) async fn new_sqlite(url: &str) -> Result<Self, DatabaseError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(pool_max_connections())
            .after_connect(|conn, _| {
                Box::pin(async move {
                    // SQLite enforces foreign keys only when enabled per connection.
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *conn)
                        .await?;
                    // SQLite's busy handler polls unfairly, so 5s starved
                    // BEGIN IMMEDIATE waiters into SQLITE_BUSY under load. Set
                    // first so the WAL switch below waits rather than failing busy.
                    sqlx::query("PRAGMA busy_timeout = 15000")
                        .execute(&mut *conn)
                        .await?;
                    // WAL keeps readers off the writer's lock; being a file
                    // property this re-asserts it per connection. SQLite answers
                    // with the mode in force, not an error, if WAL cannot apply.
                    let mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode = WAL")
                        .fetch_one(&mut *conn)
                        .await?;
                    if !mode.eq_ignore_ascii_case("wal") {
                        log_warn!(
                            "SQLite journal_mode is '{}', not WAL: readers will queue behind writes",
                            mode
                        );
                    }
                    Ok(())
                })
            })
            .connect(url)
            .await
            .map_err(|e| {
                DatabaseError::PoolError(format!("Failed to create SQLite database pool: {}", e))
            })?;

        let database_pool = DatabasePool::SQLite(pool);
        database_pool
            .create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        Ok(database_pool)
    }

    async fn create_tables(&self) -> Result<(), String> {
        match self {
            DatabasePool::MySQL(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log_error!("Failed to acquire MySQL connection: {}", e);
                    e.to_string()
                })?;
                for query in schema::mysql_table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log_error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
            }
            DatabasePool::PostgreSQL(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log_error!("Failed to acquire PostgreSQL connection: {}", e);
                    e.to_string()
                })?;
                for query in schema::postgres_table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log_error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
            }
            DatabasePool::SQLite(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log_error!("Failed to acquire SQLite connection: {}", e);
                    e.to_string()
                })?;
                for query in schema::sqlite_table_creation_queries() {
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

pub fn get_zone_token_policy_repository() -> Box<dyn repository::ZoneTokenPolicyRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_token_policy_repository(pool)
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

/// Return a zone version repository backed by the global pool.
pub fn get_zone_version_repository() -> Box<dyn repository::ZoneVersionRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_version_repository(pool)
}

/// Return a catalog zone state repository backed by the global pool.
pub fn get_catalog_zone_state_repository() -> Box<dyn repository::CatalogZoneStateRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_catalog_zone_state_repository(pool)
}

/// Return a DNSSEC key repository backed by the global pool.
pub fn get_dnssec_key_repository() -> Box<dyn repository::DnssecKeyRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_dnssec_key_repository(pool)
}

/// Return a DNSSEC record repository backed by the global pool.
pub fn get_dnssec_record_repository() -> Box<dyn repository::DnssecRecordRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_dnssec_record_repository(pool)
}
