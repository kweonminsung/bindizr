//! Backend-agnostic repository traits, the cross-backend transaction type, and
//! the factory that builds per-backend implementations.

pub(crate) mod mysql;
pub(crate) mod postgres;
pub(crate) mod sql;
pub(crate) mod sqlite;

use async_trait::async_trait;
use bindizr_core::dns::name::OwnerName;
use chrono::{DateTime, Utc};
use sqlx::{MySql, Postgres, Sqlite};

use super::model::{
    api_token::ApiToken,
    dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
    dnssec_policy::DnssecPolicy,
    dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    record::{Record, RecordType, RecordWithZone},
    tsig_key::TsigKey,
    zone::Zone,
    zone_change::ZoneChange,
    zone_token_policy::ZoneTokenPolicy,
    zone_tsig_policy::ZoneTsigPolicy,
    zone_version::ZoneVersion,
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
    pub mname: Option<String>,
    pub rname: Option<String>,
    pub default_ttl: Option<i32>,
    pub min_default_ttl: Option<i32>,
    pub max_default_ttl: Option<i32>,
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
    /// Matched through a subquery on `zones.name`, so the filter still lands
    /// on `records.zone_id` and keeps the listing on `idx_records_zone_name`
    /// while resolving the name as of the query rather than an earlier read.
    pub zone_name: Option<String>,
    pub name: Option<String>,
    pub record_type: Option<RecordType>,
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

/// Optional criteria for querying derived DNSSEC records. Value, search, and
/// priority have no derived-plane meaning, so the filter has no slot for them.
#[derive(Clone, Debug, Default)]
pub struct DnssecRecordFilter {
    /// Matched as in `RecordFilter`.
    pub zone_name: Option<String>,
    pub name: Option<String>,
    /// The wire RR type number, the column form.
    pub record_type: Option<i32>,
    pub ttl: Option<i32>,
    pub min_ttl: Option<i32>,
    pub max_ttl: Option<i32>,
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
    // IMMEDIATE takes SQLite's write lock up front so a read-then-write
    // transaction can't fail late with "database is locked".
    begin("BEGIN IMMEDIATE").await
}

/// Begin a transaction for multi-statement reads that write nothing: SQLite
/// readers then run concurrently instead of taking the single writer slot.
pub async fn begin_read_transaction() -> Result<RepositoryTx<'static>, DatabaseError> {
    begin("BEGIN DEFERRED").await
}

/// Shared opener; only SQLite's BEGIN statement distinguishes the two.
async fn begin(sqlite_begin: &'static str) -> Result<RepositoryTx<'static>, DatabaseError> {
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
            .begin_with(sqlite_begin)
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
    async fn get_tx(
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
    /// Full-row update, except the DNSSEC-owned `dnssec_policy_id`: ordinary
    /// zone updates cannot clobber it.
    async fn update_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;
    /// Set only `dnssec_policy_id`, leaving the zone's other columns
    /// untouched; `None` marks the zone unsigned.
    async fn update_dnssec_policy_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        dnssec_policy_id: Option<i32>,
    ) -> Result<(), DatabaseError>;
    /// Zones signed under the policy: the in-use check before a delete.
    async fn count_by_dnssec_policy_id(&self, dnssec_policy_id: i32) -> Result<u64, DatabaseError>;
    /// Bump only the serial, leaving the zone's other columns untouched.
    async fn update_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), DatabaseError>;
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence operations for DNSSEC policies.
#[async_trait]
pub trait DnssecPolicyRepository: Send + Sync {
    async fn create(&self, policy: DnssecPolicy) -> Result<DnssecPolicy, DatabaseError>;
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<DnssecPolicy>, DatabaseError>;
    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, DatabaseError>;
    async fn list_all(&self) -> Result<Vec<DnssecPolicy>, DatabaseError>;
    /// Write the editable columns (the timing and hold-down fields); the
    /// key layout, algorithm, and denial mode are fixed at creation.
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        policy: DnssecPolicy,
    ) -> Result<DnssecPolicy, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
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
    async fn get(&self, id: i32) -> Result<Option<ZoneTsigPolicy>, DatabaseError>;
    async fn list(&self, zone_id: i32) -> Result<Vec<ZoneTsigPolicy>, DatabaseError>;
    /// Policies granting `tsig_key_id` rights in `zone_id`, for nsupdate
    /// authorization inside the update transaction.
    async fn list_by_zone_id_and_key_id_tx(
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
    async fn get(&self, id: i32) -> Result<Option<ZoneTokenPolicy>, DatabaseError>;
    async fn list(&self, zone_id: i32) -> Result<Vec<ZoneTokenPolicy>, DatabaseError>;
    /// Policies granting `api_token_id` rights in `zone_id`, for write
    /// authorization inside the caller's transaction.
    async fn list_by_zone_id_and_token_id_tx(
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
    async fn get(&self, id: i32) -> Result<Option<Record>, DatabaseError>;
    async fn get_with_zone(&self, id: i32) -> Result<Option<RecordWithZone>, DatabaseError>;
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Record>, DatabaseError>;
    async fn list(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError>;
    /// Records of every listed zone in one round trip.
    async fn list_by_zone_ids(&self, zone_ids: &[i32]) -> Result<Vec<Record>, DatabaseError>;
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;
    async fn list_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;
    /// One owner name holding a DS record but no NS record — a delegation a DS
    /// would orphan. Row-form name, so the apex reads as the empty string.
    /// Every zone mutation runs this, so `record_type` leads the predicate to
    /// keep it on `idx_records_zone_type`.
    async fn get_ds_name_without_ns_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<String>, DatabaseError>;
    /// Load records whose owner name is any of `names` (lowercased match). Used
    /// by bulk insert to fetch only the rows that could conflict with the batch.
    async fn list_by_names_tx(
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
    /// Journal rows with serial in `(from_serial, to_serial]` — the IXFR delta
    /// half-open interval: changes strictly after `from_serial`.
    async fn list_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;
    /// Tx variant of [`Self::list_between_serials`], for reads that must
    /// be consistent with a mutation in the same transaction.
    async fn list_between_serials_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;
    /// Prune journal rows older than `cutoff`, whole serials at a time so the
    /// remaining chain stays contiguous; requests below it fall back to AXFR.
    /// Returns the number of rows deleted.
    async fn prune_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DatabaseError>;
}

/// Persistence operations for zone versions.
#[async_trait]
pub trait ZoneVersionRepository: Send + Sync {
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, DatabaseError>;
    async fn get_by_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, DatabaseError>;
    /// Versions with serial in the closed interval `[from_serial, to_serial]`;
    /// an IXFR needs both endpoint SOAs, unlike the journal's half-open range.
    async fn list_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, DatabaseError>;
    /// List versions for a zone, newest serial first, paginated. With
    /// `user_changes_only`, serials whose journal holds only signer-generated
    /// changes are skipped; the current serial is always listed.
    async fn list(
        &self,
        zone_id: i32,
        user_changes_only: bool,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneVersion>, DatabaseError>;
    async fn count(&self, zone_id: i32, user_changes_only: bool) -> Result<u64, DatabaseError>;
    /// Tx variant of [`Self::get_by_serial`], for reads that must
    /// be consistent with a mutation in the same transaction.
    async fn get_by_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneVersion>, DatabaseError>;
    /// Prune versions older than `cutoff`, always keeping each zone's newest
    /// (the IXFR up-to-date response reads it). Returns rows deleted.
    async fn prune_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DatabaseError>;
}

/// Persistence operations for DNSSEC signing keys.
#[async_trait]
pub trait DnssecKeyRepository: Send + Sync {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        key: DnssecKey,
    ) -> Result<DnssecKey, DatabaseError>;
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, DatabaseError>;
    /// Keys sitting in `state` since before `cutoff`: the rollover work list.
    /// Keys in `state` whose stamped transition deadline has passed.
    async fn list_by_state_eligible_before(
        &self,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, DatabaseError>;
    /// Zone ids holding a key of `role` sitting in `state` longer than the
    /// zone's policy's ZSK lifetime (0 exempts the zone): the
    /// scheduled-rollover work list.
    async fn list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
        &self,
        role: DnssecKeyRole,
        state: DnssecKeyState,
        now: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError>;
    async fn count_by_state(&self, state: DnssecKeyState) -> Result<u64, DatabaseError>;
    async fn update_state_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        state: DnssecKeyState,
        changed_at: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError>;
    async fn update_max_signed_ttl_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        max_signed_ttl: i32,
    ) -> Result<(), DatabaseError>;
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;
    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError>;
}

/// Persistence operations for the derived DNSSEC plane (the signed view).
#[async_trait]
pub trait DnssecRecordRepository: Send + Sync {
    /// Insert many derived records in one statement (chunked). Ids are not
    /// returned.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), DatabaseError>;
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, DatabaseError>;
    /// Delete many derived records in as few statements as the backend's bind
    /// limit allows.
    async fn delete_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), DatabaseError>;
    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError>;
    /// Zones holding a signed view (any derived row): the signed-zone count.
    /// A staged split-key half has keys but no rows.
    async fn count_zone_ids(&self) -> Result<u64, DatabaseError>;
    /// Zones holding an RRSIG that expires within their policy's re-sign
    /// window after `now`: the re-sign work list.
    async fn list_zone_ids_expiring_within_refresh(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError>;
    /// Rows expiring within their zone's policy's re-sign window after
    /// `now`; only RRSIG rows carry `expires_at`.
    async fn count_expiring_within_refresh(&self, now: DateTime<Utc>)
    -> Result<u64, DatabaseError>;
    async fn list_by_filter_with_zone(
        &self,
        filter: DnssecRecordFilter,
    ) -> Result<Vec<DnssecRecordWithZone>, DatabaseError>;
    async fn count_by_filter(&self, filter: DnssecRecordFilter) -> Result<u64, DatabaseError>;
}

/// Persistence operations for API tokens.
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    async fn create(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DatabaseError>;
    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, DatabaseError>;
    async fn list_all(&self) -> Result<Vec<ApiToken>, DatabaseError>;
    /// Writes only the mutable columns (`description`, `expires_at`,
    /// `last_used_at`); `name`, `token`, and `is_global` are fixed at create,
    /// so callers must pass them through unchanged for the echoed row to be
    /// truthful.
    async fn update(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence for the per-zone DS-withdrawal flag: a row means the zone
/// publishes the RFC 8078 delete CDS/CDNSKEY pair instead of per-key ones.
#[async_trait]
pub trait DnssecWithdrawalRepository: Send + Sync {
    async fn create_tx(&self, tx: &mut RepositoryTx<'_>, zone_id: i32)
    -> Result<(), DatabaseError>;
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<i32>, DatabaseError>;
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, zone_id: i32)
    -> Result<(), DatabaseError>;
}

/// Persistence operations for catalog zone state.
#[async_trait]
pub trait CatalogZoneStateRepository: Send + Sync {
    /// The serial advances only when `digest` changed; returns the serial in
    /// effect after the upsert.
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError>;
}

/// Builds backend-specific repository implementations for a given pool.
pub(crate) struct RepositoryFactory;

impl RepositoryFactory {
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

    pub(crate) fn create_dnssec_policy_repository(
        pool: &DatabasePool,
    ) -> Box<dyn DnssecPolicyRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnssecPolicyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnssecPolicyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteDnssecPolicyRepository::new(sqlite_pool.clone()),
            ),
        }
    }

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

    pub(crate) fn create_zone_version_repository(
        pool: &DatabasePool,
    ) -> Box<dyn ZoneVersionRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneVersionRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneVersionRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteZoneVersionRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    pub(crate) fn create_catalog_zone_state_repository(
        pool: &DatabasePool,
    ) -> Box<dyn CatalogZoneStateRepository> {
        match pool {
            DatabasePool::MySQL(_) => Box::new(mysql::MySqlCatalogZoneStateRepository),
            DatabasePool::PostgreSQL(_) => Box::new(postgres::PostgresCatalogZoneStateRepository),
            DatabasePool::SQLite(_) => Box::new(sqlite::SqliteCatalogZoneStateRepository),
        }
    }

    pub(crate) fn create_dnssec_withdrawal_repository(
        pool: &DatabasePool,
    ) -> Box<dyn DnssecWithdrawalRepository> {
        match pool {
            DatabasePool::MySQL(_) => Box::new(mysql::MySqlDnssecWithdrawalRepository),
            DatabasePool::PostgreSQL(_) => Box::new(postgres::PostgresDnssecWithdrawalRepository),
            DatabasePool::SQLite(_) => Box::new(sqlite::SqliteDnssecWithdrawalRepository),
        }
    }

    pub(crate) fn create_dnssec_key_repository(
        pool: &DatabasePool,
    ) -> Box<dyn DnssecKeyRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnssecKeyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnssecKeyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteDnssecKeyRepository::new(sqlite_pool.clone()))
            }
        }
    }

    pub(crate) fn create_dnssec_record_repository(
        pool: &DatabasePool,
    ) -> Box<dyn DnssecRecordRepository> {
        match pool {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnssecRecordRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnssecRecordRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteDnssecRecordRepository::new(sqlite_pool.clone()),
            ),
        }
    }
}
