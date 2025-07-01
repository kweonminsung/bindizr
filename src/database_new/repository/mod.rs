pub mod mysql;
pub mod postgres;

use super::model::{
    api_token::ApiToken,
    record::{Record, RecordType},
    record_history::RecordHistory,
    zone::Zone,
    zone_history::ZoneHistory,
};
use async_trait::async_trait;

// Zone Repository Trait
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
#[async_trait]
pub trait RecordRepository: Send + Sync {
    async fn create(&self, record: Record) -> Result<Record, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, String>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, String>;
    async fn get_by_name_and_type(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Option<Record>, String>;
    async fn get_all(&self) -> Result<Vec<Record>, String>;
    async fn update(&self, record: Record) -> Result<Record, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// Zone History Repository Trait
#[async_trait]
pub trait ZoneHistoryRepository: Send + Sync {
    async fn create(&self, zone_history: ZoneHistory) -> Result<ZoneHistory, String>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneHistory>, String>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneHistory>, String>;
    async fn delete(&self, id: i32) -> Result<(), String>;
}

// Record History Repository Trait
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
    pub fn create_zone_repository(
        pool: &crate::database_new::DatabasePool,
    ) -> Box<dyn ZoneRepository> {
        match pool.get_database_type() {
            crate::database_new::DatabaseType::MySQL
            | crate::database_new::DatabaseType::SQLite => {
                Box::new(mysql::MySqlZoneRepository::new(pool.clone()))
            }
            crate::database_new::DatabaseType::PostgreSQL => {
                Box::new(postgres::PostgresZoneRepository::new(pool.clone()))
            }
        }
    }

    pub fn create_record_repository(
        pool: &crate::database_new::DatabasePool,
    ) -> Box<dyn RecordRepository> {
        match pool.get_database_type() {
            crate::database_new::DatabaseType::MySQL
            | crate::database_new::DatabaseType::SQLite => {
                Box::new(mysql::MySqlRecordRepository::new(pool.clone()))
            }
            crate::database_new::DatabaseType::PostgreSQL => {
                Box::new(postgres::PostgresRecordRepository::new(pool.clone()))
            }
        }
    }

    pub fn create_zone_history_repository(
        pool: &crate::database_new::DatabasePool,
    ) -> Box<dyn ZoneHistoryRepository> {
        match pool.get_database_type() {
            crate::database_new::DatabaseType::MySQL
            | crate::database_new::DatabaseType::SQLite => {
                Box::new(mysql::MySqlZoneHistoryRepository::new(pool.clone()))
            }
            crate::database_new::DatabaseType::PostgreSQL => {
                Box::new(postgres::PostgresZoneHistoryRepository::new(pool.clone()))
            }
        }
    }

    pub fn create_record_history_repository(
        pool: &crate::database_new::DatabasePool,
    ) -> Box<dyn RecordHistoryRepository> {
        match pool.get_database_type() {
            crate::database_new::DatabaseType::MySQL
            | crate::database_new::DatabaseType::SQLite => {
                Box::new(mysql::MySqlRecordHistoryRepository::new(pool.clone()))
            }
            crate::database_new::DatabaseType::PostgreSQL => {
                Box::new(postgres::PostgresRecordHistoryRepository::new(pool.clone()))
            }
        }
    }

    pub fn create_api_token_repository(
        pool: &crate::database_new::DatabasePool,
    ) -> Box<dyn ApiTokenRepository> {
        match pool.get_database_type() {
            crate::database_new::DatabaseType::MySQL
            | crate::database_new::DatabaseType::SQLite => {
                Box::new(mysql::MySqlApiTokenRepository::new(pool.clone()))
            }
            crate::database_new::DatabaseType::PostgreSQL => {
                Box::new(postgres::PostgresApiTokenRepository::new(pool.clone()))
            }
        }
    }
}
