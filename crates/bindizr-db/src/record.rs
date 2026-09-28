use bindizr_core::dns::name::OwnerName;

use crate::{
    Backend, Db, LockLevel, Transaction,
    error::DatabaseError,
    model::record::{Record, RecordType, RecordWithZone},
    mysql, postgres,
    sql::{RecordSort, SortOrder},
    sqlite,
    tx::TransactionKind,
};

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
    /// `token_grants` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<i32>,
    pub sort: RecordSort,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Insert many records in one chunked statement, returning them with their
/// assigned ids in input order.
pub async fn create_many_tx(
    tx: &mut Transaction<'_>,
    records: &[Record],
) -> Result<Vec<Record>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::record::create_many_tx(tx, records).await,
        TransactionKind::Postgres(tx) => postgres::record::create_many_tx(tx, records).await,
        TransactionKind::Sqlite(tx) => sqlite::record::create_many_tx(tx, records).await,
    }
}

/// Find a record by ID.
pub async fn get(db: &Db, id: i32) -> Result<Option<Record>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::record::get(pool, id).await,
        Backend::Postgres(pool) => postgres::record::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::record::get(pool, id).await,
    }
}

/// Find a record with its zone metadata.
pub async fn get_with_zone(db: &Db, id: i32) -> Result<Option<RecordWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::record::get_with_zone(pool, id).await,
        Backend::Postgres(pool) => postgres::record::get_with_zone(pool, id).await,
        Backend::Sqlite(pool) => sqlite::record::get_with_zone(pool, id).await,
    }
}

/// Find a record by ID in the current transaction.
pub async fn get_tx(
    tx: &mut Transaction<'_>,
    id: i32,
    lock_level: LockLevel,
) -> Result<Option<Record>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::record::get_tx(tx, id, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::record::get_tx(tx, id, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::record::get_tx(tx, id, lock_level).await,
    }
}

/// List records for a zone in the current transaction.
pub async fn list_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
    lock_level: LockLevel,
) -> Result<Vec<Record>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::record::list_tx(tx, zone_id, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::record::list_tx(tx, zone_id, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::record::list_tx(tx, zone_id, lock_level).await,
    }
}

/// List records at an owner name in a zone in the current transaction.
pub async fn list_by_name_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
    name: &OwnerName,
    lock_level: LockLevel,
) -> Result<Vec<Record>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::record::list_by_name_tx(tx, zone_id, name, lock_level).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::record::list_by_name_tx(tx, zone_id, name, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::record::list_by_name_tx(tx, zone_id, name, lock_level).await
        }
    }
}

/// One owner name holding a DS record but no NS record — a delegation a DS
/// would orphan. Row-form name, so the apex reads as the empty string.
/// Every zone mutation runs this, so `record_type` leads the predicate to
/// keep it on `idx_records_zone_type`.
pub async fn get_ds_name_without_ns_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
) -> Result<Option<String>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::record::get_ds_name_without_ns_tx(tx, zone_id).await,
        TransactionKind::Postgres(tx) => {
            postgres::record::get_ds_name_without_ns_tx(tx, zone_id).await
        }
        TransactionKind::Sqlite(tx) => sqlite::record::get_ds_name_without_ns_tx(tx, zone_id).await,
    }
}

/// Load records whose owner name is any of `names` (lowercased match). Used
/// by bulk insert to fetch only the rows that could conflict with the batch.
pub async fn list_by_names_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
    names: &[OwnerName],
    lock_level: LockLevel,
) -> Result<Vec<Record>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::record::list_by_names_tx(tx, zone_id, names, lock_level).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::record::list_by_names_tx(tx, zone_id, names, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::record::list_by_names_tx(tx, zone_id, names, lock_level).await
        }
    }
}

/// List matching records with their zone metadata.
pub async fn list_by_filter_with_zone(
    db: &Db,
    filter: RecordFilter,
) -> Result<Vec<RecordWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::record::list_by_filter_with_zone(pool, filter).await,
        Backend::Postgres(pool) => postgres::record::list_by_filter_with_zone(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::record::list_by_filter_with_zone(pool, filter).await,
    }
}

/// Count records matching the filter.
pub async fn count_by_filter(db: &Db, filter: RecordFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::record::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::record::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::record::count_by_filter(pool, filter).await,
    }
}

/// Update a record in the current transaction.
pub async fn update_tx(tx: &mut Transaction<'_>, record: Record) -> Result<Record, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::record::update_tx(tx, record).await,
        TransactionKind::Postgres(tx) => postgres::record::update_tx(tx, record).await,
        TransactionKind::Sqlite(tx) => sqlite::record::update_tx(tx, record).await,
    }
}

/// Delete many records in as few statements as the backend's bind limit allows.
pub async fn delete_many_tx(tx: &mut Transaction<'_>, ids: &[i32]) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::record::delete_many_tx(tx, ids).await,
        TransactionKind::Postgres(tx) => postgres::record::delete_many_tx(tx, ids).await,
        TransactionKind::Sqlite(tx) => sqlite::record::delete_many_tx(tx, ids).await,
    }
}
