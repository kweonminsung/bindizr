//! Data access: the `Db` a daemon connects to, and one module per entity
//! whose functions run its queries on whichever backend it holds.

use std::str::FromStr;

use chrono::Utc;
use sqlx::{
    MySql, Pool, Postgres, Sqlite,
    mysql::MySqlPoolOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

pub mod api_token;
pub mod catalog_zone;
pub mod dnssec_key;
pub mod dnssec_policy;
pub mod dnssec_record;
pub mod dnssec_withdrawal;
pub mod error;
mod mysql;
mod postgres;
pub mod record;
mod schema;
pub mod secondary;
mod sql;
mod sqlite;
pub mod token_grant;
pub mod transfer;
pub mod tsig_grant;
pub mod tsig_key;
mod tx;
mod utils;
pub mod zone;
pub mod zone_change;
pub mod zone_version;

use bindizr_core::config;
pub use bindizr_core::model;
use error::DatabaseError;
pub use sql::{RecordSort, SortOrder, ZoneSort};
use tx::TransactionKind;
pub use tx::{LockLevel, Transaction};

/// The database the daemon connected to: one pool on one of the three
/// backends. Every query is a root function taking it (`zone::get_by_name`)
/// and matching the backend to reach the same-named function holding the SQL.
pub struct Db(Backend);

/// Which backend `Db` holds; the root functions match on it.
pub(crate) enum Backend {
    MySql(Pool<MySql>),
    Postgres(Pool<Postgres>),
    Sqlite(Pool<Sqlite>),
}

impl Db {
    /// Connect to the configured backend and set up the schema; the daemon
    /// calls this once and holds the value.
    pub async fn connect(database: &config::DatabaseConfig) -> Result<Db, DatabaseError> {
        let backend = match database.database_type {
            config::DatabaseType::Mysql => Backend::connect_mysql(&database.mysql.url).await?,
            config::DatabaseType::Postgresql => {
                Backend::connect_postgres(&database.postgresql.url).await?
            }
            config::DatabaseType::Sqlite => {
                // The file is created on a clean install, so its directory is too.
                utils::create_parent_dir(&database.sqlite.file_path)
                    .map_err(DatabaseError::PoolError)?;
                let url = utils::to_sqlite_url(&database.sqlite.file_path)
                    .map_err(DatabaseError::PoolError)?;
                Backend::connect_sqlite(&url).await?
            }
        };

        let db = Db(backend);
        db.create_tables()
            .await
            .map_err(DatabaseError::QueryFailed)?;

        log::info!("Database pool initialized");
        Ok(db)
    }

    /// Begin a transaction on the connected backend.
    pub async fn begin(&self) -> Result<Transaction<'static>, DatabaseError> {
        // IMMEDIATE takes SQLite's write lock up front so a read-then-write
        // transaction can't fail late with "database is locked".
        self.begin_with("BEGIN IMMEDIATE").await
    }

    /// Begin a transaction for multi-statement reads that write nothing: SQLite
    /// readers then run concurrently instead of taking the single writer slot.
    pub async fn begin_read(&self) -> Result<Transaction<'static>, DatabaseError> {
        self.begin_with("BEGIN DEFERRED").await
    }

    /// Shared opener; only SQLite's BEGIN statement distinguishes the two.
    async fn begin_with(
        &self,
        sqlite_begin: &'static str,
    ) -> Result<Transaction<'static>, DatabaseError> {
        let kind = match &self.0 {
            Backend::MySql(pool) => pool.begin().await.map(TransactionKind::MySql),
            Backend::Postgres(pool) => pool.begin().await.map(TransactionKind::Postgres),
            Backend::Sqlite(pool) => pool
                .begin_with(sqlite_begin)
                .await
                .map(TransactionKind::Sqlite),
        }
        .map_err(|e| DatabaseError::TransactionFailed(e.to_string()))?;
        Ok(Transaction(kind))
    }

    /// The pool's occupancy. sqlx counts held connections, not waiters, so
    /// saturation shows as `connections` reaching `max`.
    pub fn stats(&self) -> PoolStats {
        let (connections, idle) = match &self.0 {
            Backend::MySql(pool) => (pool.size(), pool.num_idle()),
            Backend::Postgres(pool) => (pool.size(), pool.num_idle()),
            Backend::Sqlite(pool) => (pool.size(), pool.num_idle()),
        };

        PoolStats {
            connections,
            idle: idle as u32,
            max: pool_max_connections(),
        }
    }
}

/// Connect once and run a trivial query, creating neither tables nor a pool
/// to keep; `doctor` runs this when no daemon is up.
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

/// How full the connection pool is. sqlx counts held connections, not waiters,
/// so saturation shows as `connections` reaching `max`.
pub struct PoolStats {
    /// Connections the pool holds, idle and handed out alike.
    pub connections: u32,
    pub idle: u32,
    pub max: u32,
}

/// Max pooled connections, scaled to the host instead of sqlx's flat 10.
/// SQLite shares it: under WAL the pool bounds readers, not the one writer.
fn pool_max_connections() -> u32 {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    ((cores * 4) as u32).clamp(8, 64)
}

impl Backend {
    /// Connect to MySQL and return the pool.
    async fn connect_mysql(url: &str) -> Result<Self, DatabaseError> {
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

        Ok(Backend::MySql(pool))
    }

    /// Connect to PostgreSQL and return the pool.
    async fn connect_postgres(url: &str) -> Result<Self, DatabaseError> {
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

        Ok(Backend::Postgres(pool))
    }

    /// Connect to SQLite and return the pool.
    async fn connect_sqlite(url: &str) -> Result<Self, DatabaseError> {
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

        Ok(Backend::Sqlite(pool))
    }
}

impl Db {
    /// Run this backend's creation statements and seed the built-in policy.
    async fn create_tables(&self) -> Result<(), String> {
        match &self.0 {
            Backend::MySql(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire MySQL connection: {}", e);
                    e.to_string()
                })?;
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
            }
            Backend::Postgres(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire PostgreSQL connection: {}", e);
                    e.to_string()
                })?;
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
            }
            Backend::Sqlite(pool) => {
                let mut conn = pool.acquire().await.map_err(|e| {
                    log::error!("Failed to acquire SQLite connection: {}", e);
                    e.to_string()
                })?;
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
            }
        }
        Ok(())
    }
}
