use bindizr_core::model::{api_token::TokenId, role::RoleId};
use chrono::{DateTime, Utc};

use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::api_token::ApiToken, mysql,
    postgres, sqlite, tx::TransactionKind,
};

/// Insert an API token.
pub async fn create_tx(
    tx: &mut Transaction<'_>,
    token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::api_token::create_tx(tx, token).await,
        TransactionKind::Postgres(tx) => postgres::api_token::create_tx(tx, token).await,
        TransactionKind::Sqlite(tx) => sqlite::api_token::create_tx(tx, token).await,
    }
}

/// An API token by id inside the caller's transaction, locked at `lock_level`.
pub async fn get_tx(
    tx: &mut Transaction<'_>,
    id: TokenId,
    lock_level: LockLevel,
) -> Result<Option<ApiToken>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::api_token::get_tx(tx, id, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::api_token::get_tx(tx, id, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::api_token::get_tx(tx, id, lock_level).await,
    }
}

/// Find an API token by name.
pub async fn get_by_name(db: &Db, name: &str) -> Result<Option<ApiToken>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::api_token::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::api_token::get_by_name(pool, name).await,
    }
}

/// Find an API token by its stored token hash.
pub async fn get_by_token(db: &Db, token: &str) -> Result<Option<ApiToken>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::get_by_token(pool, token).await,
        Backend::Postgres(pool) => postgres::api_token::get_by_token(pool, token).await,
        Backend::Sqlite(pool) => sqlite::api_token::get_by_token(pool, token).await,
    }
}

/// List all API tokens.
pub async fn list_all(db: &Db) -> Result<Vec<ApiToken>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::list_all(pool).await,
        Backend::Postgres(pool) => postgres::api_token::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::api_token::list_all(pool).await,
    }
}

/// Stamp when the token was last used.
pub async fn update_last_used_at(
    db: &Db,
    id: TokenId,
    last_used_at: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::update_last_used_at(pool, id, last_used_at).await,
        Backend::Postgres(pool) => {
            postgres::api_token::update_last_used_at(pool, id, last_used_at).await
        }
        Backend::Sqlite(pool) => {
            sqlite::api_token::update_last_used_at(pool, id, last_used_at).await
        }
    }
}

/// Delete an API token by ID.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: TokenId) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::api_token::delete_tx(tx, id).await,
        TransactionKind::Postgres(tx) => postgres::api_token::delete_tx(tx, id).await,
        TransactionKind::Sqlite(tx) => sqlite::api_token::delete_tx(tx, id).await,
    }
}

/// List the API tokens authenticating into a role.
pub async fn list_by_role_id(db: &Db, role_id: RoleId) -> Result<Vec<ApiToken>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::list_by_role_id(pool, role_id).await,
        Backend::Postgres(pool) => postgres::api_token::list_by_role_id(pool, role_id).await,
        Backend::Sqlite(pool) => sqlite::api_token::list_by_role_id(pool, role_id).await,
    }
}
