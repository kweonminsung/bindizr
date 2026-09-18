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

/// Build the global database pool from configuration; the daemon calls this
/// once. Returns whether this startup created the schema, which is what tells
/// a first install from a restart.
pub async fn initialize() -> Result<bool, DatabaseError> {
    let bindizr_config = config::bindizr_config();

    let database_type = match bindizr_config.database.database_type {
        config::DatabaseType::Mysql => DatabaseType::MySQL,
        config::DatabaseType::Postgresql => DatabaseType::PostgreSQL,
        config::DatabaseType::Sqlite => DatabaseType::SQLite,
    };

    let database_url = match database_type {
        DatabaseType::MySQL => bindizr_config.database.mysql.url.clone(),
        DatabaseType::PostgreSQL => bindizr_config.database.postgresql.url.clone(),
        DatabaseType::SQLite => {
            // The file is created on a clean install, so its directory is too.
            utils::create_parent_dir(&bindizr_config.database.sqlite.file_path)
                .map_err(DatabaseError::PoolError)?;
            utils::to_sqlite_url(&bindizr_config.database.sqlite.file_path)
                .map_err(DatabaseError::PoolError)?
        }
    };

    let (pool, schema_created) = match database_type {
        DatabaseType::MySQL => DatabasePool::new_mysql(&database_url).await?,
        DatabaseType::PostgreSQL => DatabasePool::new_postgres(&database_url).await?,
        DatabaseType::SQLite => DatabasePool::new_sqlite(&database_url).await?,
    };

    DATABASE_POOL
        .set(pool)
        .map_err(|_| DatabaseError::PoolError("database pool initialized twice".to_string()))?;

    log::info!("Database pool initialized");
    Ok(schema_created)
}

/// Connect once and run a trivial query, creating neither tables nor the
/// global pool; `doctor` runs this when no daemon is up.
pub async fn probe_connection(database: &config::DatabaseConfig) -> Result<(), DatabaseError> {
    match database.database_type {
        config::DatabaseType::Mysql => {
            let pool = MySqlPoolOptions::new()
                .max_connections(1)
                .connect(&database.mysql.url)
                .await
                .map_err(|e| DatabaseError::PoolError(mysql_connect_error(&e)))?;
            sqlx::query("SELECT 1")
                .execute(&pool)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        }
        config::DatabaseType::Postgresql => {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&database.postgresql.url)
                .await
                .map_err(|e| DatabaseError::PoolError(postgres_connect_error(&e)))?;
            sqlx::query("SELECT 1")
                .execute(&pool)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        }
        config::DatabaseType::Sqlite => {
            // Creating the file here would leave it owned by whoever ran doctor.
            let url = utils::to_sqlite_url(&database.sqlite.file_path)
                .map_err(DatabaseError::PoolError)?;
            let connect_options = sqlite_connect_options(&url)?
                .create_if_missing(false)
                .read_only(true);
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(connect_options)
                .await
                .map_err(|e| DatabaseError::PoolError(sqlite_connect_error(&e)))?;
            sqlx::query("SELECT 1")
                .execute(&pool)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        }
    }
    Ok(())
}

/// Parse a SQLite URL into connection options.
fn sqlite_connect_options(url: &str) -> Result<SqliteConnectOptions, DatabaseError> {
    SqliteConnectOptions::from_str(url)
        .map_err(|e| DatabaseError::PoolError(format!("Invalid SQLite file path: {}", e)))
}

/// The MySQL connection failure, naming the key an operator would fix.
fn mysql_connect_error(e: &sqlx::Error) -> String {
    format!("MySQL connection failed (check database.mysql.url): {}", e)
}

/// The PostgreSQL connection failure, naming the key an operator would fix.
fn postgres_connect_error(e: &sqlx::Error) -> String {
    format!(
        "PostgreSQL connection failed (check database.postgresql.url): {}",
        e
    )
}

/// The SQLite open failure, naming the key an operator would fix.
fn sqlite_connect_error(e: &sqlx::Error) -> String {
    format!(
        "SQLite open failed (check database.sqlite.file_path): {}",
        e
    )
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
    pub(crate) async fn new_mysql(url: &str) -> Result<(Self, bool), DatabaseError> {
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
            .map_err(|e| DatabaseError::PoolError(mysql_connect_error(&e)))?;

        let database_pool = DatabasePool::MySQL(pool);
        let schema_created = database_pool
            .create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        Ok((database_pool, schema_created))
    }

    /// Connect to PostgreSQL, create tables, and return the pool.
    pub(crate) async fn new_postgres(url: &str) -> Result<(Self, bool), DatabaseError> {
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
            .map_err(|e| DatabaseError::PoolError(postgres_connect_error(&e)))?;

        let database_pool = DatabasePool::PostgreSQL(pool);
        let schema_created = database_pool
            .create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        Ok((database_pool, schema_created))
    }

    /// Connect to SQLite, create tables, and return the pool.
    pub(crate) async fn new_sqlite(url: &str) -> Result<(Self, bool), DatabaseError> {
        // A clean install points at a database file that does not exist yet.
        let connect_options = sqlite_connect_options(url)?.create_if_missing(true);

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
            .map_err(|e| DatabaseError::PoolError(sqlite_connect_error(&e)))?;

        let database_pool = DatabasePool::SQLite(pool);
        let schema_created = database_pool
            .create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        Ok((database_pool, schema_created))
    }

    /// Create the application schema in the selected database backend,
    /// reporting whether it was absent beforehand: the statements themselves
    /// are idempotent, so only this tells a first install from a restart.
    async fn create_tables(&self) -> Result<bool, String> {
        let created = match self {
            DatabasePool::MySQL(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire MySQL connection: {}", e);
                    e.to_string()
                })?;
                let existed = sqlx::query(schema::mysql::schema_presence_query())
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to read the MySQL schema: {}", e);
                        e.to_string()
                    })?
                    .is_some();
                for query in schema::mysql::table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
                let seed = schema::mysql::default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        e.to_string()
                    })?;
                !existed
            }
            DatabasePool::PostgreSQL(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire PostgreSQL connection: {}", e);
                    e.to_string()
                })?;
                let existed = sqlx::query(schema::postgres::schema_presence_query())
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to read the PostgreSQL schema: {}", e);
                        e.to_string()
                    })?
                    .is_some();
                for query in schema::postgres::table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
                let seed = schema::postgres::default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        e.to_string()
                    })?;
                !existed
            }
            DatabasePool::SQLite(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire SQLite connection: {}", e);
                    e.to_string()
                })?;
                let existed = sqlx::query(schema::sqlite::schema_presence_query())
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to read the SQLite schema: {}", e);
                        e.to_string()
                    })?
                    .is_some();
                for query in schema::sqlite::table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        e.to_string()
                    })?;
                }
                let seed = schema::sqlite::default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        e.to_string()
                    })?;
                !existed
            }
        };
        Ok(created)
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
