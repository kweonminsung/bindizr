pub mod mysql;
pub mod postgres;
pub mod sqlite;

use super::model::{
    api_token::ApiToken,
    record::{Record, RecordType},
    record_history::RecordHistory,
    zone::Zone,
    zone_history::ZoneHistory,
};
use crate::database::DatabasePool;
use async_trait::async_trait;

// Zone Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait ZoneRepository: Send + Sync {
    async fn create(&self, zone: Zone) -> Result<Zone, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, String>;
    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, String>;
    async fn get_all(&self) -> Result<Vec<Zone>, String>;
    async fn update(&self, zone: Zone) -> Result<Zone, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// Record Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait RecordRepository: Send + Sync {
    async fn create(&self, record: Record) -> Result<Record, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, String>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, String>;
    async fn get_by_name_and_type(
        &self,
        name: &str,
        record_type: &RecordType,
    ) -> Result<Option<Record>, String>;
    async fn get_records_by_name(&self, name: &str) -> Result<Vec<Record>, String>;
    async fn get_all(&self) -> Result<Vec<Record>, String>;
    async fn update(&self, record: Record) -> Result<Record, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// Zone History Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait ZoneHistoryRepository: Send + Sync {
    async fn create(&self, zone_history: ZoneHistory) -> Result<ZoneHistory, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneHistory>, String>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneHistory>, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// Record History Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait RecordHistoryRepository: Send + Sync {
    async fn create(&self, record_history: RecordHistory) -> Result<RecordHistory, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<RecordHistory>, String>;
    async fn get_by_record_id(&self, record_id: i32) -> Result<Vec<RecordHistory>, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// API Token Repository Trait
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    async fn create(&self, token: ApiToken) -> Result<ApiToken, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ApiToken>, String>;
    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, String>;
    async fn get_all(&self) -> Result<Vec<ApiToken>, String>;
    async fn update(&self, token: ApiToken) -> Result<ApiToken, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// Repository Factory
pub struct RepositoryFactory;

impl RepositoryFactory {
    pub fn create_zone_repository(pool: &DatabasePool) -> Box<dyn ZoneRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => {
                Box::new(postgres::PostgresZoneRepository::new(postgres_pool.clone()))
            }
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteZoneRepository::new(sqlite_pool.clone()))
            }
        }
    }

    pub fn create_record_repository(pool: &DatabasePool) -> Box<dyn RecordRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlRecordRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresRecordRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteRecordRepository::new(sqlite_pool.clone()))
            }
        }
    }

    pub fn create_zone_history_repository(pool: &DatabasePool) -> Box<dyn ZoneHistoryRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneHistoryRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneHistoryRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteZoneHistoryRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    pub fn create_record_history_repository(
        pool: &DatabasePool,
    ) -> Box<dyn RecordHistoryRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlRecordHistoryRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresRecordHistoryRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteRecordHistoryRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    pub fn create_api_token_repository(pool: &DatabasePool) -> Box<dyn ApiTokenRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlApiTokenRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresApiTokenRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteApiTokenRepository::new(sqlite_pool.clone()))
            }
        }
    }
}
