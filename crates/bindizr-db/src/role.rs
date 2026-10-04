use bindizr_core::model::role::RoleId;

use crate::{
    Backend, Db, Transaction, error::DatabaseError, model::role::Role, mysql, postgres, sqlite,
    tx::TransactionKind,
};

/// Insert a role.
pub async fn create_tx(tx: &mut Transaction<'_>, role: Role) -> Result<Role, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role::create_tx(tx, role).await,
        TransactionKind::Postgres(tx) => postgres::role::create_tx(tx, role).await,
        TransactionKind::Sqlite(tx) => sqlite::role::create_tx(tx, role).await,
    }
}

/// Find a role by ID.
pub async fn get(db: &Db, id: RoleId) -> Result<Option<Role>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::get(pool, id).await,
        Backend::Postgres(pool) => postgres::role::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::role::get(pool, id).await,
    }
}

/// Find a role by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<Role>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::role::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::role::get_by_name(pool, name).await,
    }
}

/// List all roles.
pub async fn list_all(db: &Db) -> Result<Vec<Role>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role::list_all(pool).await,
        Backend::Postgres(pool) => postgres::role::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::role::list_all(pool).await,
    }
}

/// Delete a role by ID; its grants go with it.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: RoleId) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role::delete_tx(tx, id).await,
        TransactionKind::Postgres(tx) => postgres::role::delete_tx(tx, id).await,
        TransactionKind::Sqlite(tx) => sqlite::role::delete_tx(tx, id).await,
    }
}
