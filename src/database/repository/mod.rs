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
use crate::database::{DatabasePool, error::DatabaseError, model::{dns_instance::DnsInstance, dns_key::DnsKey}};
use async_trait::async_trait;

// Zone Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait ZoneRepository: Send + Sync {
    async fn create(&self, zone: Zone) -> Result<Zone, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<Zone>, DatabaseError>;
    async fn update(&self, zone: Zone) -> Result<Zone, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

// Record Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait RecordRepository: Send + Sync {
    async fn create(&self, record: Record) -> Result<Record, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, DatabaseError>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError>;
    async fn get_by_name_and_type(
        &self,
        name: &str,
        record_type: &RecordType,
    ) -> Result<Option<Record>, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Vec<Record>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<Record>, DatabaseError>;
    async fn update(&self, record: Record) -> Result<Record, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

// Zone History Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait ZoneHistoryRepository: Send + Sync {
    async fn create(&self, zone_history: ZoneHistory) -> Result<ZoneHistory, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneHistory>, DatabaseError>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneHistory>, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

// Record History Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait RecordHistoryRepository: Send + Sync {
    async fn create(&self, record_history: RecordHistory) -> Result<RecordHistory, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<RecordHistory>, DatabaseError>;
    async fn get_by_record_id(&self, record_id: i32) -> Result<Vec<RecordHistory>, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

// DNS Instance Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait DnsInstanceRepository: Send + Sync {
    async fn create(&self, dns_instance: DnsInstance) -> Result<DnsInstance, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<DnsInstance>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<DnsInstance>, DatabaseError>;
    async fn update(&self, dns_instance: DnsInstance) -> Result<DnsInstance, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

// DNS Key Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait DnsKeyRepository: Send + Sync {
    async fn create(&self, dns_key: DnsKey) -> Result<DnsKey, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<DnsKey>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<DnsKey>, DatabaseError>;
    async fn update(&self, dns_key: DnsKey) -> Result<DnsKey, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

// API Token Repository Trait
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    async fn create(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ApiToken>, DatabaseError>;
    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<ApiToken>, DatabaseError>;
    async fn update(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
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

    pub fn create_dns_instance_repository(pool: &DatabasePool) -> Box<dyn DnsInstanceRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnsInstanceRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnsInstanceRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteDnsInstanceRepository::new(sqlite_pool.clone()))
            }
        }
    }

    pub fn create_dns_key_repository(pool: &DatabasePool) -> Box<dyn DnsKeyRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnsKeyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnsKeyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteDnsKeyRepository::new(sqlite_pool.clone()))
            }
        }
    }
}