//! Data access: the `Db` a daemon connects to, and one module per entity
//! whose functions run its queries on whichever backend it holds.

use std::str::FromStr;

use chrono::Utc;
use sqlx::{
    MySql, Pool, Postgres, Sqlite,
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    postgres::{PgConnectOptions, PgPoolOptions},
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
pub mod role;
pub mod role_grant;
mod schema;
pub mod secondary;
mod sql;
mod sqlite;
pub mod transfer;
pub mod tsig_key;
mod tx;
mod utils;
pub mod zone;
pub mod zone_change;
pub mod zone_version;

pub use bindizr_core::model;
use bindizr_core::{
    config,
    model::{
        role::Role,
        role_grant::{Action, ActionSet},
    },
};
use error::DatabaseError;
pub use sql::{ParseSortError, RecordSortField, SortOrder, ZoneSortField};
use tx::TransactionKind;
pub use tx::{LockLevel, Transaction};

/// What the built-in role is described as.
const ADMIN_ROLE_DESCRIPTION: &str = "every action in all zones";

/// One backend connection pool, passed to entity functions such as
/// `zone::get_by_name` that dispatch to backend-specific SQL.
#[derive(Debug)]
pub struct Db(Backend);

/// Which backend `Db` holds; the root functions match on it.
#[derive(Debug)]
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
            config::DatabaseType::MySql => {
                Backend::connect_mysql(&database.mysql.url, &database.tls).await?
            }
            config::DatabaseType::Postgres => {
                Backend::connect_postgres(&database.postgresql.url, &database.tls).await?
            }
            config::DatabaseType::Sqlite => {
                // The file is created on a clean install, so its directory is too.
                utils::create_parent_dir(&database.sqlite.file_path)?;
                let url = utils::to_sqlite_url(&database.sqlite.file_path)?;
                Backend::connect_sqlite(&url).await?
            }
        };

        let db = Db(backend);
        db.create_tables().await?;

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
        .map_err(DatabaseError::TransactionFailed)?;
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
        config::DatabaseType::MySql => {
            let pool = MySqlPoolOptions::new()
                .max_connections(1)
                .connect_with(mysql_connect_options(&database.mysql.url, &database.tls)?)
                .await
                .map_err(DatabaseError::MySqlConnect)?;
            sqlx::query("SELECT 1").execute(&pool).await?;
        }
        config::DatabaseType::Postgres => {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(postgres_connect_options(
                    &database.postgresql.url,
                    &database.tls,
                )?)
                .await
                .map_err(DatabaseError::PostgresConnect)?;
            sqlx::query("SELECT 1").execute(&pool).await?;
        }
        config::DatabaseType::Sqlite => {
            // Creating the file here would leave it owned by whoever ran doctor.
            let url = utils::to_sqlite_url(&database.sqlite.file_path)?;
            let connect_options = sqlite_connect_options(&url)?
                .create_if_missing(false)
                .read_only(true);
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(connect_options)
                .await
                .map_err(DatabaseError::SqliteOpen)?;
            sqlx::query("SELECT 1").execute(&pool).await?;
        }
    }
    Ok(())
}

/// Parse a SQLite URL into connection options.
fn sqlite_connect_options(url: &str) -> Result<SqliteConnectOptions, DatabaseError> {
    SqliteConnectOptions::from_str(url).map_err(DatabaseError::InvalidSqlitePath)
}

/// Parse the MySQL URL and lay `[database.tls]` over it: a set key replaces
/// the URL's own parameter.
fn mysql_connect_options(
    url: &str,
    tls: &config::DatabaseTlsConfig,
) -> Result<MySqlConnectOptions, DatabaseError> {
    let mut options = MySqlConnectOptions::from_str(url).map_err(DatabaseError::MySqlConnect)?;
    if let Some(mode) = tls.mode {
        options = options.ssl_mode(mode.into());
    }
    if let Some(ca_file) = &tls.ca_file {
        options = options.ssl_ca(ca_file);
    }
    Ok(options)
}

/// Parse the PostgreSQL URL and lay `[database.tls]` over it: a set key
/// replaces the URL's own parameter.
fn postgres_connect_options(
    url: &str,
    tls: &config::DatabaseTlsConfig,
) -> Result<PgConnectOptions, DatabaseError> {
    let mut options = PgConnectOptions::from_str(url).map_err(DatabaseError::PostgresConnect)?;
    if let Some(mode) = tls.mode {
        options = options.ssl_mode(mode.into());
    }
    if let Some(ca_file) = &tls.ca_file {
        options = options.ssl_root_cert(ca_file);
    }
    Ok(options)
}

/// How full the connection pool is. sqlx counts held connections, not waiters,
/// so saturation shows as `connections` reaching `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    async fn connect_mysql(
        url: &str,
        tls: &config::DatabaseTlsConfig,
    ) -> Result<Self, DatabaseError> {
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
            .connect_with(mysql_connect_options(url, tls)?)
            .await
            .map_err(DatabaseError::MySqlConnect)?;

        Ok(Backend::MySql(pool))
    }

    /// Connect to PostgreSQL and return the pool.
    async fn connect_postgres(
        url: &str,
        tls: &config::DatabaseTlsConfig,
    ) -> Result<Self, DatabaseError> {
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
            .connect_with(postgres_connect_options(url, tls)?)
            .await
            .map_err(DatabaseError::PostgresConnect)?;

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
            .map_err(DatabaseError::SqliteOpen)?;

        Ok(Backend::Sqlite(pool))
    }
}

impl Db {
    /// Run this backend's creation statements and seed the built-in policy and role.
    async fn create_tables(&self) -> Result<(), DatabaseError> {
        match &self.0 {
            Backend::MySql(pool) => {
                let mut conn = pool.acquire().await?;
                for query in schema::mysql::table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        DatabaseError::from(e)
                    })?;
                }
                let seed = schema::mysql::default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
                let seed = schema::mysql::admin_role_seed();
                sqlx::query(seed)
                    .bind(Role::ADMIN)
                    .bind(ADMIN_ROLE_DESCRIPTION)
                    .bind(Utc::now())
                    .bind(Role::ADMIN)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
                let seed = schema::mysql::admin_grant_seed();
                sqlx::query(seed)
                    .bind(ActionSet::from_iter(Action::ALL))
                    .bind(Utc::now())
                    .bind(Role::ADMIN)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
            }
            Backend::Postgres(pool) => {
                let mut conn = pool.acquire().await?;
                for query in schema::postgres::table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        DatabaseError::from(e)
                    })?;
                }
                let seed = schema::postgres::default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
                let seed = schema::postgres::admin_role_seed();
                sqlx::query(seed)
                    .bind(Role::ADMIN)
                    .bind(ADMIN_ROLE_DESCRIPTION)
                    .bind(Utc::now())
                    .bind(Role::ADMIN)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
                let seed = schema::postgres::admin_grant_seed();
                sqlx::query(seed)
                    .bind(ActionSet::from_iter(Action::ALL))
                    .bind(Utc::now())
                    .bind(Role::ADMIN)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
            }
            Backend::Sqlite(pool) => {
                let mut conn = pool.acquire().await?;
                for query in schema::sqlite::table_creation_queries() {
                    sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", query, e);
                        DatabaseError::from(e)
                    })?;
                }
                let seed = schema::sqlite::default_policy_seed();
                sqlx::query(seed)
                    .bind(Utc::now())
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
                let seed = schema::sqlite::admin_role_seed();
                sqlx::query(seed)
                    .bind(Role::ADMIN)
                    .bind(ADMIN_ROLE_DESCRIPTION)
                    .bind(Utc::now())
                    .bind(Role::ADMIN)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
                let seed = schema::sqlite::admin_grant_seed();
                sqlx::query(seed)
                    .bind(ActionSet::from_iter(Action::ALL))
                    .bind(Utc::now())
                    .bind(Role::ADMIN)
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to execute query '{}': {}", seed, e);
                        DatabaseError::from(e)
                    })?;
            }
        }
        Ok(())
    }
}
