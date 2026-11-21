use bindizr_core::model::role::{Role, RoleId, RoleWithCounts};

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{Backend, Db, Transaction, mysql, postgres, sqlite};

/// Insert a role.
pub async fn create_tx(tx: &mut Transaction<'_>, role: Role) -> Result<Role, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role::create_tx(tx, role).await,
        TransactionKind::Postgres(tx) => postgres::role::create_tx(tx, role).await,
        TransactionKind::Sqlite(tx) => sqlite::role::create_tx(tx, role).await,
    }
}

/// Get a role by ID.
pub async fn get(db: &Db, role_id: RoleId) -> Result<Option<Role>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::get(pool, role_id).await,
        Backend::Postgres(pool) => postgres::role::get(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::role::get(pool, role_id).await,
    }
}

/// Get a role by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<Role>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::role::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::role::get_by_name(pool, name).await,
    }
}

/// Delete a role by ID; its grants go with it. Reports `false` when no row had
/// the id.
pub async fn delete_tx(tx: &mut Transaction<'_>, role_id: RoleId) -> Result<bool, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role::delete_tx(tx, role_id).await,
        TransactionKind::Postgres(tx) => postgres::role::delete_tx(tx, role_id).await,
        TransactionKind::Sqlite(tx) => sqlite::role::delete_tx(tx, role_id).await,
    }
}

/// List roles with their grant and credential counts in name order, applying the supplied window.
pub async fn list_all_with_counts(
    db: &Db,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<RoleWithCounts>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::list_all_with_counts(pool, limit, offset).await,
        Backend::Postgres(pool) => postgres::role::list_all_with_counts(pool, limit, offset).await,
        Backend::Sqlite(pool) => sqlite::role::list_all_with_counts(pool, limit, offset).await,
    }
}

/// Get a role by name with its grant and credential counts.
pub async fn get_by_name_with_counts(
    db: &Db,
    name: &str,
) -> Result<Option<RoleWithCounts>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::get_by_name_with_counts(pool, name).await,
        Backend::Postgres(pool) => postgres::role::get_by_name_with_counts(pool, name).await,
        Backend::Sqlite(pool) => sqlite::role::get_by_name_with_counts(pool, name).await,
    }
}

/// Count all roles.
pub async fn count_all(db: &Db) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::count_all(pool).await,
        Backend::Postgres(pool) => postgres::role::count_all(pool).await,
        Backend::Sqlite(pool) => sqlite::role::count_all(pool).await,
    }
}
