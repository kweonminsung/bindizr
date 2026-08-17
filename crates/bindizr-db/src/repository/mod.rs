//! Backend-agnostic repository traits, the cross-backend transaction type, and
//! the factory that builds per-backend implementations.

pub(crate) mod mysql;
pub(crate) mod postgres;
pub(crate) mod sql;
pub(crate) mod sqlite;

use async_trait::async_trait;
use bindizr_core::dns::name::OwnerName;
use sqlx::{MySql, Postgres, Sqlite};

use super::model::{
    api_token::ApiToken,
    record::{Record, RecordWithZone},
    tsig_key::TsigKey,
    zone::Zone,
    zone_change::ZoneChange,
    zone_snapshot::ZoneSnapshot,
    zone_token_policy::ZoneTokenPolicy,
    zone_tsig_policy::ZoneTsigPolicy,
};
use crate::{DatabasePool, error::DatabaseError, get_pool};

/// How strongly a transactional read locks the rows it returns. Every `_tx`
/// read names one, so the locking model reads off the call site. Granularity
/// is the backend's: MySQL and PostgreSQL lock rows, SQLite's whole-database
/// write lock already covers every level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockLevel {
    /// The caller mutates these rows in this transaction.
    Exclusive,
    /// The caller only derives output from these rows, but they must not
    /// change before it commits.
    Shared,
    /// None needed: a lock the caller already holds — in practice the zone row,
    /// which every zone-data mutation takes first — covers these rows.
    None,
}

/// Optional criteria for querying zones.
#[derive(Clone, Debug, Default)]
pub struct ZoneFilter {
    pub name: Option<String>,
    pub id: Option<i32>,
    pub primary_ns: Option<String>,
    pub admin_email: Option<String>,
    pub ttl: Option<i32>,
    pub min_ttl: Option<i32>,
    pub max_ttl: Option<i32>,
    pub serial: Option<i32>,
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `zone_token_policies` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<i32>,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Optional criteria for querying records.
#[derive(Clone, Debug, Default)]
pub struct RecordFilter {
    pub zone_name: Option<String>,
    pub name: Option<String>,
    pub record_type: Option<String>,
    pub value: Option<String>,
    pub ttl: Option<i32>,
    pub min_ttl: Option<i32>,
    pub max_ttl: Option<i32>,
    pub priority: Option<i32>,
    pub min_priority: Option<i32>,
    pub max_priority: Option<i32>,
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `zone_token_policies` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<i32>,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// A database transaction spanning any of the supported backends.
pub struct RepositoryTx<'a>(RepositoryTxKind<'a>);

enum RepositoryTxKind<'a> {
    MySQL(sqlx::Transaction<'a, MySql>),
    PostgreSQL(sqlx::Transaction<'a, Postgres>),
    SQLite(sqlx::Transaction<'a, Sqlite>),
}

/// Begin a transaction on the global database pool.
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
        // BEGIN IMMEDIATE takes SQLite's write lock up front so a read-then-write
        // transaction can't fail late with "database is locked".
        DatabasePool::SQLite(pool) => pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map(|tx| RepositoryTx(RepositoryTxKind::SQLite(tx)))
            .map_err(|e| DatabaseError::TransactionFailed(e.to_string())),
    }
}

impl<'a> RepositoryTx<'a> {
    /// Commit the transaction.
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

    /// Roll back the transaction.
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

    /// Borrow the underlying MySQL transaction, erroring if this handle wraps a
    /// different backend.
    pub(crate) fn as_mysql(&mut self) -> Result<&mut sqlx::Transaction<'a, MySql>, DatabaseError> {
        match &mut self.0 {
            RepositoryTxKind::MySQL(tx) => Ok(tx),
            _ => Err(DatabaseError::TransactionFailed(
                "transaction kind mismatch (expected MySQL)".to_string(),
            )),
        }
    }

    /// Borrow the underlying PostgreSQL transaction, erroring if this handle
    /// wraps a different backend.
    pub(crate) fn as_postgres(
        &mut self,
    ) -> Result<&mut sqlx::Transaction<'a, Postgres>, DatabaseError> {
        match &mut self.0 {
            RepositoryTxKind::PostgreSQL(tx) => Ok(tx),
            _ => Err(DatabaseError::TransactionFailed(
                "transaction kind mismatch (expected PostgreSQL)".to_string(),
            )),
        }
    }

    /// Borrow the underlying SQLite transaction, erroring if this handle wraps a
    /// different backend.
    pub(crate) fn as_sqlite(
        &mut self,
    ) -> Result<&mut sqlx::Transaction<'a, Sqlite>, DatabaseError> {
        match &mut self.0 {
            RepositoryTxKind::SQLite(tx) => Ok(tx),
            _ => Err(DatabaseError::TransactionFailed(
                "transaction kind mismatch (expected SQLite)".to_string(),
            )),
        }
    }
}

/// Persistence operations for zones.
#[async_trait]
pub trait ZoneRepository: Send + Sync {
    async fn create_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;
    async fn get_by_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError>;
    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError>;
    async fn list_all(&self) -> Result<Vec<Zone>, DatabaseError>;
    async fn list_all_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        lock_level: LockLevel,
    ) -> Result<Vec<Zone>, DatabaseError>;
    async fn list_by_filter(&self, filter: ZoneFilter) -> Result<Vec<Zone>, DatabaseError>;
    async fn count_by_filter(&self, filter: ZoneFilter) -> Result<u64, DatabaseError>;
    /// Limit-1 probe of the zones table; health checks must stay cheap on
    /// large tables.
    async fn ping(&self) -> Result<(), DatabaseError>;
    async fn update_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;
    /// Bump only the serial, leaving the zone's other columns untouched.
    async fn update_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), DatabaseError>;
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence operations for TSIG keys.
#[async_trait]
pub trait TsigKeyRepository: Send + Sync {
    async fn create(&self, key: TsigKey) -> Result<TsigKey, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<TsigKey>, DatabaseError>;
    async fn list_all(&self) -> Result<Vec<TsigKey>, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence operations for zone TSIG policies.
#[async_trait]
pub trait ZoneTsigPolicyRepository: Send + Sync {
    async fn create(&self, policy: ZoneTsigPolicy) -> Result<ZoneTsigPolicy, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneTsigPolicy>, DatabaseError>;
    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneTsigPolicy>, DatabaseError>;
    /// Policies granting `tsig_key_id` rights in `zone_id`, for nsupdate
    /// authorization inside the update transaction.
    async fn list_by_zone_and_key_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneTsigPolicy>, DatabaseError>;
    async fn count_by_key_id(&self, tsig_key_id: i32) -> Result<u64, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence operations for zone token policies, the HTTP twin of
/// [`ZoneTsigPolicyRepository`].
#[async_trait]
pub trait ZoneTokenPolicyRepository: Send + Sync {
    async fn create(&self, policy: ZoneTokenPolicy) -> Result<ZoneTokenPolicy, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneTokenPolicy>, DatabaseError>;
    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneTokenPolicy>, DatabaseError>;
    /// Policies granting `api_token_id` rights in `zone_id`, for write
    /// authorization inside the caller's transaction.
    async fn list_by_zone_and_token_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneTokenPolicy>, DatabaseError>;
    /// Every policy granted to `api_token_id`; drives what a scoped token can
    /// see and NOTIFY.
    async fn list_by_token_id(
        &self,
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence operations for records.
#[async_trait]
pub trait RecordRepository: Send + Sync {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError>;
    /// Insert many records in one chunked statement, returning them with their
    /// assigned ids in input order.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, DatabaseError>;
    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, DatabaseError>;
    async fn get_by_id_with_zone(&self, id: i32) -> Result<Option<RecordWithZone>, DatabaseError>;
    async fn get_by_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Record>, DatabaseError>;
    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError>;
    /// Records of every listed zone in one round trip.
    async fn list_by_zone_ids(&self, zone_ids: &[i32]) -> Result<Vec<Record>, DatabaseError>;
    async fn list_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;
    async fn list_by_zone_id_and_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;
    /// Load records whose owner name is any of `names` (lowercased match). Used
    /// by bulk insert to fetch only the rows that could conflict with the batch.
    async fn list_by_zone_id_and_names_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[OwnerName],
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;
    async fn list_by_filter_with_zone(
        &self,
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, DatabaseError>;
    async fn count_by_filter(&self, filter: RecordFilter) -> Result<u64, DatabaseError>;
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError>;
    /// Delete many records in as few statements as the backend's bind limit allows.
    async fn delete_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), DatabaseError>;
}

/// Persistence operations for zone changes.
#[async_trait]
pub trait ZoneChangeRepository: Send + Sync {
    /// Insert many zone changes in one statement (chunked). Ids are not returned.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError>;
    async fn list_changes_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;
    /// Tx variant of [`Self::list_changes_between_serials`], for reads that must
    /// be consistent with a mutation in the same transaction.
    async fn list_changes_between_serials_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;
}

/// Persistence operations for zone snapshots.
#[async_trait]
pub trait ZoneSnapshotRepository: Send + Sync {
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
    /// Fetch every snapshot for a zone whose serial is in `[from_serial, to_serial]`.
    async fn list_by_zone_id_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneSnapshot>, DatabaseError>;
    /// List snapshots for a zone, newest serial first, paginated.
    async fn list_by_zone_id(
        &self,
        zone_id: i32,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneSnapshot>, DatabaseError>;
    async fn count_by_zone_id(&self, zone_id: i32) -> Result<u64, DatabaseError>;
    /// Tx variant of [`Self::get_by_zone_id_and_serial`], for reads that must
    /// be consistent with a mutation in the same transaction.
    async fn get_by_zone_id_and_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneSnapshot>, DatabaseError>;
}

/// Persistence operations for API tokens.
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    async fn create(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DatabaseError>;
    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, DatabaseError>;
    async fn list_all(&self) -> Result<Vec<ApiToken>, DatabaseError>;
    async fn update(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence operations for catalog zone state.
#[async_trait]
pub trait CatalogZoneStateRepository: Send + Sync {
    /// Returns the catalog serial in effect after the update.
    async fn update_serial_for_signature_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError>;
}

/// Builds backend-specific repository implementations for a given pool.
pub(crate) struct RepositoryFactory;

impl RepositoryFactory {
    /// Create a zone repository for the given pool's backend.
    pub(crate) fn create_zone_repository(pool: &DatabasePool) -> Box<dyn ZoneRepository> {
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

    /// Create a record repository for the given pool's backend.
    pub(crate) fn create_record_repository(pool: &DatabasePool) -> Box<dyn RecordRepository> {
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

    /// Create a TSIG key repository for the given pool's backend.
    pub(crate) fn create_tsig_key_repository(pool: &DatabasePool) -> Box<dyn TsigKeyRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlTsigKeyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresTsigKeyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteTsigKeyRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// Create a zone TSIG policy repository for the given pool's backend.
    pub(crate) fn create_zone_tsig_policy_repository(
        pool: &DatabasePool,
    ) -> Box<dyn ZoneTsigPolicyRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => Box::new(mysql::MySqlZoneTsigPolicyRepository::new(
                mysql_pool.clone(),
            )),
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneTsigPolicyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteZoneTsigPolicyRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    pub(crate) fn create_zone_token_policy_repository(
        pool: &DatabasePool,
    ) -> Box<dyn ZoneTokenPolicyRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => Box::new(
                mysql::MySqlZoneTokenPolicyRepository::new(mysql_pool.clone()),
            ),
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneTokenPolicyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteZoneTokenPolicyRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    /// Create an API token repository for the given pool's backend.
    pub(crate) fn create_api_token_repository(pool: &DatabasePool) -> Box<dyn ApiTokenRepository> {
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

    /// Create a zone change repository for the given pool's backend.
    pub(crate) fn create_zone_change_repository(
        pool: &DatabasePool,
    ) -> Box<dyn ZoneChangeRepository> {
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

    /// Create a zone snapshot repository for the given pool's backend.
    pub(crate) fn create_zone_snapshot_repository(
        pool: &DatabasePool,
    ) -> Box<dyn ZoneSnapshotRepository> {
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

    /// Create a catalog zone state repository for the given pool's backend.
    pub(crate) fn create_catalog_zone_state_repository(
        pool: &DatabasePool,
    ) -> Box<dyn CatalogZoneStateRepository> {
        match pool {
            DatabasePool::MySQL(_) => Box::new(mysql::MySqlCatalogZoneStateRepository),
            DatabasePool::PostgreSQL(_) => Box::new(postgres::PostgresCatalogZoneStateRepository),
            DatabasePool::SQLite(_) => Box::new(sqlite::SqliteCatalogZoneStateRepository),
        }
    }
}
