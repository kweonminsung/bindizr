use bindizr_core::model::dnssec_policy::PolicyId;

use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::dnssec_policy::DnssecPolicy,
    mysql, postgres, sqlite, tx::TransactionKind,
};

/// Insert a DNSSEC policy.
pub async fn create(db: &Db, policy: DnssecPolicy) -> Result<DnssecPolicy, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_policy::create(pool, policy).await,
        Backend::Postgres(pool) => postgres::dnssec_policy::create(pool, policy).await,
        Backend::Sqlite(pool) => sqlite::dnssec_policy::create(pool, policy).await,
    }
}

/// Find a DNSSEC policy by ID in the current transaction.
pub async fn get_tx(
    tx: &mut Transaction<'_>,
    id: PolicyId,
    lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_policy::get_tx(tx, id, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_policy::get_tx(tx, id, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_policy::get_tx(tx, id, lock_level).await,
    }
}

/// Find a DNSSEC policy by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<DnssecPolicy>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_policy::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::dnssec_policy::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::dnssec_policy::get_by_name(pool, name).await,
    }
}

/// Find a DNSSEC policy by name in the current transaction.
pub async fn get_by_name_tx(
    tx: &mut Transaction<'_>,
    name: &str,
    lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::dnssec_policy::get_by_name_tx(tx, name, lock_level).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_policy::get_by_name_tx(tx, name, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::dnssec_policy::get_by_name_tx(tx, name, lock_level).await
        }
    }
}

/// List all DNSSEC policies.
pub async fn list_all(db: &Db) -> Result<Vec<DnssecPolicy>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_policy::list_all(pool).await,
        Backend::Postgres(pool) => postgres::dnssec_policy::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::dnssec_policy::list_all(pool).await,
    }
}

/// Write the editable timing fields; the
/// key layout, algorithm, and denial mode are fixed at creation.
pub async fn update_tx(
    tx: &mut Transaction<'_>,
    policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_policy::update_tx(tx, policy).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_policy::update_tx(tx, policy).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_policy::update_tx(tx, policy).await,
    }
}

/// Delete a DNSSEC policy by ID.
pub async fn delete(db: &Db, id: PolicyId) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_policy::delete(pool, id).await,
        Backend::Postgres(pool) => postgres::dnssec_policy::delete(pool, id).await,
        Backend::Sqlite(pool) => sqlite::dnssec_policy::delete(pool, id).await,
    }
}
