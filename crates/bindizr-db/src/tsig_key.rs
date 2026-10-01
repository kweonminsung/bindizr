use bindizr_core::model::{role::RoleId, tsig_key::TsigKeyId};

use crate::{Backend, Db, error::DatabaseError, model::tsig_key::TsigKey, mysql, postgres, sqlite};

/// Insert a TSIG key.
pub async fn create(db: &Db, key: TsigKey) -> Result<TsigKey, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::create(pool, key).await,
        Backend::Postgres(pool) => postgres::tsig_key::create(pool, key).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::create(pool, key).await,
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
pub async fn delete(db: &Db, id: TsigKeyId) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::delete(pool, id).await,
        Backend::Postgres(pool) => postgres::tsig_key::delete(pool, id).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::delete(pool, id).await,
    }
}

/// Count the TSIG keys authenticating into a role: the in-use check before a role delete.
pub async fn count_by_role_id(db: &Db, role_id: RoleId) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_key::count_by_role_id(pool, role_id).await,
        Backend::Postgres(pool) => postgres::tsig_key::count_by_role_id(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::tsig_key::count_by_role_id(pool, role_id).await,
    }
}
