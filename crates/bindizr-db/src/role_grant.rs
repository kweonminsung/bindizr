use bindizr_core::model::role::RoleId;
use bindizr_core::model::role_grant::{RoleGrant, RoleGrantId, RoleGrantWithZone};

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{Backend, Db, Transaction, mysql, postgres, sqlite};

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

/// Get a role grant by ID.
pub async fn get(db: &Db, grant_id: RoleGrantId) -> Result<Option<RoleGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role_grant::get(pool, grant_id).await,
        Backend::Postgres(pool) => postgres::role_grant::get(pool, grant_id).await,
        Backend::Sqlite(pool) => sqlite::role_grant::get(pool, grant_id).await,
    }
}

/// List every grant of a role, which bounds what a credential of it may see.
pub async fn list_by_role_id(db: &Db, role_id: RoleId) -> Result<Vec<RoleGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role_grant::list_by_role_id(pool, role_id).await,
        Backend::Postgres(pool) => postgres::role_grant::list_by_role_id(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::role_grant::list_by_role_id(pool, role_id).await,
    }
}

/// List every grant of a role in the current transaction, share-locked
/// (`FOR SHARE` on MySQL/PostgreSQL), for a mutation to authorize against.
pub async fn list_by_role_id_tx(
    tx: &mut Transaction<'_>,
    role_id: RoleId,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role_grant::list_by_role_id_tx(tx, role_id).await,
        TransactionKind::Postgres(tx) => {
            postgres::role_grant::list_by_role_id_tx(tx, role_id).await
        }
        TransactionKind::Sqlite(tx) => sqlite::role_grant::list_by_role_id_tx(tx, role_id).await,
    }
}

/// Delete a role grant by ID.
/// Reports `false` when no row had the id.
pub async fn delete_tx(
    tx: &mut Transaction<'_>,
    grant_id: RoleGrantId,
) -> Result<bool, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::role_grant::delete_tx(tx, grant_id).await,
        TransactionKind::Postgres(tx) => postgres::role_grant::delete_tx(tx, grant_id).await,
        TransactionKind::Sqlite(tx) => sqlite::role_grant::delete_tx(tx, grant_id).await,
    }
}

/// List a role's grants with zone names in id order, applying the supplied window.
pub async fn list_by_role_id_with_zone(
    db: &Db,
    role_id: RoleId,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<RoleGrantWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::role_grant::list_by_role_id_with_zone(pool, role_id, limit, offset).await
        }
        Backend::Postgres(pool) => {
            postgres::role_grant::list_by_role_id_with_zone(pool, role_id, limit, offset).await
        }
        Backend::Sqlite(pool) => {
            sqlite::role_grant::list_by_role_id_with_zone(pool, role_id, limit, offset).await
        }
    }
}

/// Count the grants of one role.
pub async fn count_by_role_id(db: &Db, role_id: RoleId) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::role_grant::count_by_role_id(pool, role_id).await,
        Backend::Postgres(pool) => postgres::role_grant::count_by_role_id(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::role_grant::count_by_role_id(pool, role_id).await,
    }
}
