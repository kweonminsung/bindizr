use bindizr_core::model::role::RoleId;
use bindizr_core::model::tsig_key::{TsigKey, TsigKeyId, TsigKeyMetadata};

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{Backend, Db, LockLevel, Transaction, mysql, postgres, sqlite};

/// Insert a TSIG key.
pub async fn create_tx(
    tx: &mut Transaction<'_>,
    tsig_key: TsigKey,
) -> Result<TsigKey, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::tsig_key::create_tx(tx, tsig_key).await,
        TransactionKind::Postgres(tx) => postgres::tsig_key::create_tx(tx, tsig_key).await,
        TransactionKind::Sqlite(tx) => sqlite::tsig_key::create_tx(tx, tsig_key).await,
    }
}

/// Get a TSIG key by ID.
pub async fn get(db: &Db, id: TsigKeyId) -> Result<Option<TsigKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::get(pool, id).await,
        Backend::Postgres(pool) => postgres::tsig_key::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::get(pool, id).await,
    }
}

/// Get a TSIG key by ID in the current transaction, locked at `lock_level`.
pub async fn get_tx(
    tx: &mut Transaction<'_>,
    id: TsigKeyId,
    lock_level: LockLevel,
) -> Result<Option<TsigKey>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::tsig_key::get_tx(tx, id, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::tsig_key::get_tx(tx, id, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::tsig_key::get_tx(tx, id, lock_level).await,
    }
}

/// Get a TSIG key by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<TsigKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::tsig_key::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::get_by_name(pool, name).await,
    }
}

/// Delete a TSIG key by ID.
/// Reports `false` when no row had the id.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: TsigKeyId) -> Result<bool, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::tsig_key::delete_tx(tx, id).await,
        TransactionKind::Postgres(tx) => postgres::tsig_key::delete_tx(tx, id).await,
        TransactionKind::Sqlite(tx) => sqlite::tsig_key::delete_tx(tx, id).await,
    }
}

/// List the TSIG keys authenticating into a role.
pub async fn list_by_role_id(db: &Db, role_id: RoleId) -> Result<Vec<TsigKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::list_by_role_id(pool, role_id).await,
        Backend::Postgres(pool) => postgres::tsig_key::list_by_role_id(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::list_by_role_id(pool, role_id).await,
    }
}

/// Role selection and a validated window for metadata listings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TsigKeyFilter {
    pub role_id: Option<RoleId>,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// List credential metadata with its role name, filtered and paged in SQL.
pub async fn list_by_filter_with_role(
    db: &Db,
    filter: &TsigKeyFilter,
) -> Result<Vec<TsigKeyMetadata>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::list_by_filter_with_role(pool, filter).await,
        Backend::Postgres(pool) => postgres::tsig_key::list_by_filter_with_role(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::list_by_filter_with_role(pool, filter).await,
    }
}

/// Count credentials matching the role filter, ignoring its page window.
pub async fn count_by_filter(db: &Db, filter: &TsigKeyFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::tsig_key::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::count_by_filter(pool, filter).await,
    }
}
