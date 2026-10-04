use bindizr_core::model::{role::RoleId, tsig_key::TsigKeyId};

use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::tsig_key::TsigKey, mysql,
    postgres, sqlite, tx::TransactionKind,
};

/// Insert a TSIG key.
pub async fn create_tx(tx: &mut Transaction<'_>, key: TsigKey) -> Result<TsigKey, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::tsig_key::create_tx(tx, key).await,
        TransactionKind::Postgres(tx) => postgres::tsig_key::create_tx(tx, key).await,
        TransactionKind::Sqlite(tx) => sqlite::tsig_key::create_tx(tx, key).await,
    }
}

/// Find a TSIG key by ID.
pub async fn get(db: &Db, id: TsigKeyId) -> Result<Option<TsigKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::get(pool, id).await,
        Backend::Postgres(pool) => postgres::tsig_key::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::get(pool, id).await,
    }
}

/// A TSIG key by id inside the caller's transaction, locked at `lock_level`.
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

/// Find a TSIG key by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<TsigKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::tsig_key::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::get_by_name(pool, name).await,
    }
}

/// List all TSIG keys.
pub async fn list_all(db: &Db) -> Result<Vec<TsigKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::list_all(pool).await,
        Backend::Postgres(pool) => postgres::tsig_key::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::list_all(pool).await,
    }
}

/// Delete a TSIG key by ID.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: TsigKeyId) -> Result<(), DatabaseError> {
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
