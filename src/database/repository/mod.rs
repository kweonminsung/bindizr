pub mod mysql;
pub mod postgres;
pub mod sqlite;

use super::model::{
    api_token::ApiToken,
    record::{Record, RecordType},
    zone::Zone,
    zone_change::ZoneChange,
    zone_snapshot::ZoneSnapshot,
};
use crate::database::{DatabasePool, error::DatabaseError, get_pool};
use async_trait::async_trait;
use sqlx::{MySql, Postgres, Sqlite};

pub struct RepositoryTx<'a>(RepositoryTxKind<'a>);

enum RepositoryTxKind<'a> {
    MySQL(sqlx::Transaction<'a, MySql>),
    PostgreSQL(sqlx::Transaction<'a, Postgres>),
    SQLite(sqlx::Transaction<'a, Sqlite>),
}

pub async fn begin_transaction() -> Result<RepositoryTx<'static>, DatabaseError> {
    match get_pool() {
        DatabasePool::MySQL(pool) => pool
            .begin()
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::MySQL(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        DatabasePool::PostgreSQL(pool) => pool
            .begin()
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::PostgreSQL(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        DatabasePool::SQLite(pool) => pool
            .begin()
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::SQLite(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
    }
}

impl<'a> RepositoryTx<'a> {
    pub async fn commit(self) -> Result<(), DatabaseError> {
        match self.0 {
            RepositoryTxKind::MySQL(tx) => tx
                .commit()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::PostgreSQL(tx) => tx
                .commit()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::SQLite(tx) => tx
                .commit()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        }
    }

    pub async fn rollback(self) -> Result<(), DatabaseError> {
        match self.0 {
            RepositoryTxKind::MySQL(tx) => tx
                .rollback()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::PostgreSQL(tx) => tx
                .rollback()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
            RepositoryTxKind::SQLite(tx) => tx
                .rollback()
                .await
                .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
        }
    }
}

// Zone Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait ZoneRepository: Send + Sync {
    async fn create(&self, zone: Zone) -> Result<Zone, DatabaseError>;
    async fn create_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError>;
    async fn get_by_name_for_update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
    ) -> Result<Option<Zone>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<Zone>, DatabaseError>;
    async fn update(&self, zone: Zone) -> Result<Zone, DatabaseError>;
    async fn update_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;
}

// Record Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait RecordRepository: Send + Sync {
    async fn create(&self, record: Record) -> Result<Record, DatabaseError>;
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, DatabaseError>;
    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError>;
    async fn get_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, DatabaseError>;
    async fn get(
        &self,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, DatabaseError>;
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, DatabaseError>;
    async fn get_all(&self) -> Result<Vec<Record>, DatabaseError>;
    async fn update(&self, record: Record) -> Result<Record, DatabaseError>;
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;
}

// Zone Change Repository Trait
#[allow(dead_code)]
#[async_trait]
pub trait ZoneChangeRepository: Send + Sync {
    async fn create(&self, zone_change: ZoneChange) -> Result<ZoneChange, DatabaseError>;
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_change: ZoneChange,
    ) -> Result<ZoneChange, DatabaseError>;
    async fn get_changes_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;
}

#[allow(dead_code)]
#[async_trait]
pub trait ZoneSnapshotRepository: Send + Sync {
    async fn upsert(&self, snapshot: ZoneSnapshot) -> Result<ZoneSnapshot, DatabaseError>;
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, DatabaseError>;
    async fn get_by_zone_id_and_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, DatabaseError>;
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

    pub fn create_zone_change_repository(pool: &DatabasePool) -> Box<dyn ZoneChangeRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneChangeRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneChangeRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteZoneChangeRepository::new(sqlite_pool.clone()))
            }
        }
    }

    pub fn create_zone_snapshot_repository(pool: &DatabasePool) -> Box<dyn ZoneSnapshotRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneSnapshotRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneSnapshotRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteZoneSnapshotRepository::new(sqlite_pool.clone()),
            ),
        }
    }
}
