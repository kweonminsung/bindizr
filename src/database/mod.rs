use crate::{config, log_error, log_info};
use sqlx::{MySql, Pool, Postgres, Sqlite};
use std::sync::OnceLock;

pub mod model;
pub mod repository;
mod schema;
mod utils;

static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();

#[derive(Debug)]
pub enum DatabasePool {
    MySQL(Pool<MySql>),
    PostgreSQL(Pool<Postgres>),
    SQLite(Pool<Sqlite>),
}

#[derive(Debug, Clone)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    SQLite,
}

impl DatabaseType {
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "mysql" => Ok(DatabaseType::MySQL),
            "postgresql" | "postgres" | "pg" => Ok(DatabaseType::PostgreSQL),
            "sqlite" => Ok(DatabaseType::SQLite),
            _ => Err(format!("Unsupported database type: {}", s)),
        }
    }
}

pub async fn initialize() {
    let database_type_str = config::get_config::<String>("database.type");
    let database_type = DatabaseType::from_str(&database_type_str).unwrap_or_else(|e| {
        log_error!("{}", e);
        std::process::exit(1);
    });

    let database_url = match database_type {
        DatabaseType::MySQL => config::get_config::<String>("database.mysql.server_url"),
        DatabaseType::PostgreSQL => config::get_config::<String>("database.postgres.server_url"),
        DatabaseType::SQLite => {
            utils::to_sqlite_url(&config::get_config::<String>("database.sqlite.file_path"))
                .unwrap_or_else(|e| {
                    log_error!("{}", e);
                    std::process::exit(1);
                })
        }
    };

    let pool = match database_type {
        DatabaseType::MySQL => DatabasePool::new_mysql(&database_url).await,
        DatabaseType::PostgreSQL => DatabasePool::new_postgres(&database_url).await,
        DatabaseType::SQLite => DatabasePool::new_sqlite(&database_url).await,
    };

    DATABASE_POOL
        .set(pool)
        .expect("Failed to set database pool");

    log_info!("Database pool initialized");
}

pub fn get_pool() -> &'static DatabasePool {
    DATABASE_POOL.get().expect("Database pool not initialized")
}

impl DatabasePool {
    pub async fn new_mysql(url: &str) -> Self {
        let pool = Pool::<MySql>::connect(url).await.unwrap_or_else(|e| {
            log_error!("Failed to create MySQL database pool: {}", e);
            std::process::exit(1);
        });

        let database_pool = DatabasePool::MySQL(pool);

        // Create tables
        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }

    pub async fn new_postgres(url: &str) -> Self {
        let pool = Pool::<Postgres>::connect(url).await.unwrap_or_else(|e| {
            log_error!("Failed to create PostgreSQL database pool: {}", e);
            std::process::exit(1);
        });

        let database_pool = DatabasePool::PostgreSQL(pool);

        // Create tables
        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }

    pub async fn new_sqlite(url: &str) -> Self {
        let pool = Pool::<Sqlite>::connect(url).await.unwrap_or_else(|e| {
            log_error!("Failed to create SQLite database pool: {}", e);
            std::process::exit(1);
        });

        let database_pool = DatabasePool::SQLite(pool);

        // Enable foreign key constraints for SQLite
        if let DatabasePool::SQLite(ref pool) = database_pool {
            let mut conn = pool.acquire().await.unwrap_or_else(|e| {
                log_error!("Failed to acquire SQLite connection: {}", e);
                std::process::exit(1);
            });
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(&mut *conn)
                .await
                .unwrap_or_else(|e| {
                    log_error!("Failed to enable foreign keys: {}", e);
                    std::process::exit(1);
                });
        }

        // Create tables
        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }

    async fn create_tables(&self) -> Result<(), String> {
        // Get table creation queries from schema module based on database type
        let queries = match self {
            DatabasePool::MySQL(_) => schema::get_mysql_table_creation_queries(),
            DatabasePool::PostgreSQL(_) => schema::get_postgres_table_creation_queries(),
            DatabasePool::SQLite(_) => schema::get_sqlite_table_creation_queries(),
        };

        match self {
            DatabasePool::MySQL(pool) => {
                for query in queries {
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
                for query in queries {
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
                for query in queries {
                    let mut conn = pool.acquire().await.map_err(|e| {
                        log_error!("Failed to acquire SQLite connection: {}", e);
                        e.to_string()
                    })?;
                    // Enable foreign key constraints for each connection
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *conn)
                        .await
                        .map_err(|e| {
                            log_error!("Failed to enable foreign keys: {}", e);
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

// Repository convenience functions - returns trait objects for runtime dispatch
pub fn get_zone_repository() -> Box<dyn repository::ZoneRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_repository(pool)
}

pub fn get_record_repository() -> Box<dyn repository::RecordRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_record_repository(pool)
}

pub fn get_zone_history_repository() -> Box<dyn repository::ZoneHistoryRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_zone_history_repository(pool)
}

pub fn get_record_history_repository() -> Box<dyn repository::RecordHistoryRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_record_history_repository(pool)
}

pub fn get_api_token_repository() -> Box<dyn repository::ApiTokenRepository> {
    let pool = get_pool();
    repository::RepositoryFactory::create_api_token_repository(pool)
}
