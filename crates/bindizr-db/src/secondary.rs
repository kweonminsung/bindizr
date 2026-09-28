use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::secondary::Secondary, mysql,
    postgres, sqlite, tx::TransactionKind,
};

/// Insert a secondary.
pub async fn create(db: &Db, secondary: Secondary) -> Result<Secondary, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::secondary::create(pool, secondary).await,
        Backend::Postgres(pool) => postgres::secondary::create(pool, secondary).await,
        Backend::Sqlite(pool) => sqlite::secondary::create(pool, secondary).await,
    }
}

/// Find a secondary by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<Secondary>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::secondary::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::secondary::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::secondary::get_by_name(pool, name).await,
    }
}

/// Find a secondary by name in the current transaction.
pub async fn get_by_name_tx(
    tx: &mut Transaction<'_>,
    name: &str,
    lock_level: LockLevel,
) -> Result<Option<Secondary>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::secondary::get_by_name_tx(tx, name, lock_level).await,
        TransactionKind::Postgres(tx) => {
            postgres::secondary::get_by_name_tx(tx, name, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::secondary::get_by_name_tx(tx, name, lock_level).await
        }
    }
}

/// Find a secondary by address.
pub async fn get_by_address(db: &Db, address: &str) -> Result<Option<Secondary>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::secondary::get_by_address(pool, address).await,
        Backend::Postgres(pool) => postgres::secondary::get_by_address(pool, address).await,
        Backend::Sqlite(pool) => sqlite::secondary::get_by_address(pool, address).await,
    }
}

/// List all secondaries, disabled ones included.
pub async fn list_all(db: &Db) -> Result<Vec<Secondary>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::secondary::list_all(pool).await,
        Backend::Postgres(pool) => postgres::secondary::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::secondary::list_all(pool).await,
    }
}

/// Write the address and enabled flag; the name is fixed at creation.
pub async fn update_tx(
    tx: &mut Transaction<'_>,
    secondary: Secondary,
) -> Result<Secondary, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::secondary::update_tx(tx, secondary).await,
        TransactionKind::Postgres(tx) => postgres::secondary::update_tx(tx, secondary).await,
        TransactionKind::Sqlite(tx) => sqlite::secondary::update_tx(tx, secondary).await,
    }
}

/// Secondaries whose NOTIFY the key signs: the in-use check before a key
/// delete.
pub async fn count_by_notify_tsig_key_id(db: &Db, tsig_key_id: i32) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::secondary::count_by_notify_tsig_key_id(pool, tsig_key_id).await
        }
        Backend::Postgres(pool) => {
            postgres::secondary::count_by_notify_tsig_key_id(pool, tsig_key_id).await
        }
        Backend::Sqlite(pool) => {
            sqlite::secondary::count_by_notify_tsig_key_id(pool, tsig_key_id).await
        }
    }
}

/// Delete a secondary by ID.
pub async fn delete(db: &Db, id: i32) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::secondary::delete(pool, id).await,
        Backend::Postgres(pool) => postgres::secondary::delete(pool, id).await,
        Backend::Sqlite(pool) => sqlite::secondary::delete(pool, id).await,
    }
}
