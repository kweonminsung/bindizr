//! Database layer: connection-pool setup and repository implementations for
//! the MySQL, PostgreSQL, and SQLite backends.

use std::{str::FromStr, sync::OnceLock};

use chrono::Utc;
use sqlx::{
    MySql, Pool, Postgres, Sqlite,
    mysql::MySqlPoolOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

pub mod error;
pub mod repository;
mod schema;
mod utils;

pub(crate) use bindizr_core::config;
pub use bindizr_core::model;
use error::DatabaseError;

static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();

#[derive(Debug)]
pub(crate) enum DatabasePool {
    MySQL(Pool<MySql>),
    PostgreSQL(Pool<Postgres>),
    SQLite(Pool<Sqlite>),
}

#[derive(Debug, Clone)]
pub(crate) enum DatabaseType {
    MySQL,
    PostgreSQL,
    SQLite,
}

/// Build the global database pool from configuration; the daemon calls this once.
pub async fn initialize() -> Result<(), DatabaseError> {
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

    DATABASE_POOL
        .set(pool)
        .map_err(|_| DatabaseError::PoolError("database pool initialized twice".to_string()))?;

    log::info!("Database pool initialized");
    Ok(())
}

/// Return the global database pool, panicking if not yet initialized.
pub(crate) fn pool() -> &'static DatabasePool {
    DATABASE_POOL.get().expect("Database pool not initialized")
}

/// How full the connection pool is. sqlx counts held connections, not waiters,
/// so saturation shows as `connections` reaching `max`.
pub struct PoolStats {
    /// Connections the pool holds, idle and handed out alike.
    pub connections: u32,
    pub idle: u32,
    pub max: u32,
}

/// The pool's occupancy, or `None` before [`initialize`].
pub fn pool_stats() -> Option<PoolStats> {
    let (connections, idle) = match DATABASE_POOL.get()? {
        DatabasePool::MySQL(pool) => (pool.size(), pool.num_idle()),
        DatabasePool::PostgreSQL(pool) => (pool.size(), pool.num_idle()),
        DatabasePool::SQLite(pool) => (pool.size(), pool.num_idle()),
    };

    Some(PoolStats {
        connections,
        idle: idle as u32,
        max: pool_max_connections(),
    })
}

/// Max pooled connections, scaled to the host instead of sqlx's flat 10.
/// SQLite shares it: under WAL the pool bounds readers, not the one writer.
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
        // A clean install points at a database file that does not exist yet.
        let connect_options = SqliteConnectOptions::from_str(url)
            .map_err(|e| DatabaseError::PoolError(format!("Invalid SQLite file path: {}", e)))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(pool_max_connections())
            .after_connect(|conn, _| {
                Box::pin(async move {
                    // SQLite enforces foreign keys only when enabled per connection.
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *conn)
                        .await?;
                    // SQLite's busy handler polls unfairly: a short timeout starves
                    // BEGIN IMMEDIATE waiters into SQLITE_BUSY. Set before the WAL
                    // switch, which locks too.
                    sqlx::query("PRAGMA busy_timeout = 15000")
                        .execute(&mut *conn)
                        .await?;
                    // WAL keeps readers off the writer's lock; a file property, so
                    // each connection re-asserts it. SQLite reports the mode in
                    // force instead of failing when WAL cannot apply.
                    let mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode = WAL")
                        .fetch_one(&mut *conn)
                        .await?;
                    if !mode.eq_ignore_ascii_case("wal") {
                        log::warn!(
                            "SQLite journal_mode is '{}', not WAL: readers will queue behind writes",
                            mode
                        );
                    }
                    Ok(())
                })
            })
            .connect_with(connect_options)
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

    /// Create the application schema in the selected database backend.
    async fn create_tables(&self) -> Result<(), String> {
        match self {
            DatabasePool::MySQL(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire MySQL connection: {}", e);
                    e.to_string()
                })?;
                for query in schema::mysql_table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
                let seed = schema::mysql_default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        e.to_string()
                    })?;
            }
            DatabasePool::PostgreSQL(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire PostgreSQL connection: {}", e);
                    e.to_string()
                })?;
                for query in schema::postgres_table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
                let seed = schema::postgres_default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        e.to_string()
                    })?;
            }
            DatabasePool::SQLite(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire SQLite connection: {}", e);
                    e.to_string()
                })?;
                for query in schema::sqlite_table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
                let seed = schema::sqlite_default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        e.to_string()
                    })?;
            }
        }
        Ok(())
    }
}

/// Return the initialized zone repository.
pub fn get_zone_repository() -> Box<dyn repository::ZoneRepository> {
    pool().zone_repository()
}

/// Return the initialized record repository.
pub fn get_record_repository() -> Box<dyn repository::RecordRepository> {
    pool().record_repository()
}

/// Return the initialized DNSSEC policy repository.
pub fn get_dnssec_policy_repository() -> Box<dyn repository::DnssecPolicyRepository> {
    pool().dnssec_policy_repository()
}

/// Return the initialized TSIG key repository.
pub fn get_tsig_key_repository() -> Box<dyn repository::TsigKeyRepository> {
    pool().tsig_key_repository()
}

/// Return the initialized TSIG grant repository.
pub fn get_tsig_grant_repository() -> Box<dyn repository::TsigGrantRepository> {
    pool().tsig_grant_repository()
}

/// Return the initialized token grant repository.
pub fn get_token_grant_repository() -> Box<dyn repository::TokenGrantRepository> {
    pool().token_grant_repository()
}

/// Return the initialized API token repository.
pub fn get_api_token_repository() -> Box<dyn repository::ApiTokenRepository> {
    pool().api_token_repository()
}

/// Return the initialized zone change repository.
pub fn get_zone_change_repository() -> Box<dyn repository::ZoneChangeRepository> {
    pool().zone_change_repository()
}

/// Return the initialized zone version repository.
pub fn get_zone_version_repository() -> Box<dyn repository::ZoneVersionRepository> {
    pool().zone_version_repository()
}

/// Return the initialized catalog zone state repository.
pub fn get_catalog_zone_state_repository() -> Box<dyn repository::CatalogZoneStateRepository> {
    pool().catalog_zone_state_repository()
}

/// Return the initialized DNSSEC withdrawal repository.
pub fn get_dnssec_withdrawal_repository() -> Box<dyn repository::DnssecWithdrawalRepository> {
    pool().dnssec_withdrawal_repository()
}

/// Return the initialized DNSSEC key repository.
pub fn get_dnssec_key_repository() -> Box<dyn repository::DnssecKeyRepository> {
    pool().dnssec_key_repository()
}

/// Return the initialized DNSSEC record repository.
pub fn get_dnssec_record_repository() -> Box<dyn repository::DnssecRecordRepository> {
    pool().dnssec_record_repository()
}
