use crate::{config, log_error, log_info};
use sqlx::{Any, AnyPool, Pool, Transaction, pool::PoolConnection};
use std::sync::OnceLock;

pub mod model;
pub mod repository;
mod schema;
mod utils;

static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct DatabasePool {
    pool: Pool<Any>,
    database_type: DatabaseType,
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

    sqlx::any::install_default_drivers();

    let pool = DatabasePool::new(&database_url, database_type).await;
    DATABASE_POOL
        .set(pool)
        .expect("Failed to set database pool");

    log_info!("Database pool initialized");
}

pub fn get_pool() -> &'static DatabasePool {
    DATABASE_POOL.get().expect("Database pool not initialized")
}

impl DatabasePool {
    pub async fn new(url: &str, database_type: DatabaseType) -> Self {
        let pool = Pool::<Any>::connect(url).await.unwrap_or_else(|e| {
            log_error!("Failed to create database pool: {}", e);
            std::process::exit(1);
        });

        let database_pool = DatabasePool {
            pool,
            database_type,
        };

        // Create tables
        if let Err(e) = database_pool.create_tables().await {
            log_error!("Failed to create tables: {}", e);
            std::process::exit(1);
        }

        database_pool
    }

    async fn create_tables(&self) -> Result<(), String> {
        let mut conn = self.get_connection().await?;

        // Get table creation queries from schema module based on database type
        let queries = match self.database_type {
            DatabaseType::MySQL => schema::get_mysql_table_creation_queries(),
            DatabaseType::PostgreSQL => schema::get_postgres_table_creation_queries(),
            DatabaseType::SQLite => schema::get_sqlite_table_creation_queries(),
        };

        for query in queries {
            sqlx::query(query).execute(&mut *conn).await.map_err(|e| {
                log_error!("Failed to execute query '{}': {}", query, e);
                e.to_string()
            })?;
        }
        Ok(())
    }

    async fn get_connection(&self) -> Result<PoolConnection<Any>, String> {
        self.pool.acquire().await.map_err(|e| {
            log_error!("Failed to acquire database connection: {}", e);
            e.to_string()
        })
    }

    pub fn get_database_type(&self) -> &DatabaseType {
        &self.database_type
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

pub async fn start_transaction() -> Result<Transaction<'static, Any>, sqlx::Error> {
    let pool: AnyPool = get_pool().pool.clone();

    let tx = pool.begin().await?;

    Ok(tx)
}
