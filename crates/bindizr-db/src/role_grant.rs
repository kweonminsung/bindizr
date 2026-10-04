use bindizr_core::model::{role::RoleId, role_grant::RoleGrantId, zone::ZoneId};

use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::role_grant::RoleGrant, mysql,
    postgres, sqlite, tx::TransactionKind,
};

/// Insert a role grant.
pub async fn create_tx(
    tx: &mut Transaction<'_>,
    grant: RoleGrant,
) -> Result<RoleGrant, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role_grant::create_tx(tx, grant).await,
        TransactionKind::Postgres(tx) => postgres::role_grant::create_tx(tx, grant).await,
        TransactionKind::Sqlite(tx) => sqlite::role_grant::create_tx(tx, grant).await,
    }
}

/// Find a role grant by ID.
pub async fn get(db: &Db, id: RoleGrantId) -> Result<Option<RoleGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role_grant::get(pool, id).await,
        Backend::Postgres(pool) => postgres::role_grant::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::role_grant::get(pool, id).await,
    }
}

/// Every grant of a role; drives what a credential authenticating into it may
/// List every role's grants.
pub async fn list_all(db: &Db) -> Result<Vec<RoleGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role_grant::list_all(pool).await,
        Backend::Postgres(pool) => postgres::role_grant::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::role_grant::list_all(pool).await,
    }
}

/// Every grant of a role, which bounds what a credential of it may see.
pub async fn list_by_role_id(db: &Db, role_id: RoleId) -> Result<Vec<RoleGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role_grant::list_by_role_id(pool, role_id).await,
        Backend::Postgres(pool) => postgres::role_grant::list_by_role_id(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::role_grant::list_by_role_id(pool, role_id).await,
    }
}

/// Every grant of a role inside the caller's transaction, locked at
/// `lock_level`, for a mutation to authorize against.
pub async fn list_by_role_id_tx(
    tx: &mut Transaction<'_>,
    role_id: RoleId,
    lock_level: LockLevel,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::role_grant::list_by_role_id_tx(tx, role_id, lock_level).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::role_grant::list_by_role_id_tx(tx, role_id, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::role_grant::list_by_role_id_tx(tx, role_id, lock_level).await
        }
    }
}

/// A role's grants that reach `zone_id`, its all-zones grants included, for
/// write authorization inside the caller's transaction.
pub async fn list_by_role_id_covering_zone_tx(
    tx: &mut Transaction<'_>,
    role_id: RoleId,
    zone_id: ZoneId,
    lock_level: LockLevel,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::role_grant::list_by_role_id_covering_zone_tx(tx, role_id, zone_id, lock_level)
                .await
        }
        TransactionKind::Postgres(tx) => {
            postgres::role_grant::list_by_role_id_covering_zone_tx(tx, role_id, zone_id, lock_level)
                .await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::role_grant::list_by_role_id_covering_zone_tx(tx, role_id, zone_id, lock_level)
                .await
        }
    }
}

/// Delete a role grant by ID.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: RoleGrantId) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role_grant::delete_tx(tx, id).await,
        TransactionKind::Postgres(tx) => postgres::role_grant::delete_tx(tx, id).await,
        TransactionKind::Sqlite(tx) => sqlite::role_grant::delete_tx(tx, id).await,
    }
}
