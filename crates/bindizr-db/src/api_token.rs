use bindizr_core::model::api_token::TokenId;

use crate::{
    Backend, Db, error::DatabaseError, model::api_token::ApiToken, mysql, postgres, sqlite,
};

/// Insert an API token.
pub async fn create(db: &Db, token: ApiToken) -> Result<ApiToken, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::create(pool, token).await,
        Backend::Postgres(pool) => postgres::api_token::create(pool, token).await,
        Backend::Sqlite(pool) => sqlite::api_token::create(pool, token).await,
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

/// Writes only the mutable columns (`description`, `expires_at`,
/// `last_used_at`); `name`, `token`, and `is_global` are fixed at create,
/// so callers must pass them through unchanged for the echoed row to be
/// truthful.
pub async fn update(db: &Db, token: ApiToken) -> Result<ApiToken, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::update(pool, token).await,
        Backend::Postgres(pool) => postgres::api_token::update(pool, token).await,
        Backend::Sqlite(pool) => sqlite::api_token::update(pool, token).await,
    }
}

/// Delete an API token by ID.
pub async fn delete(db: &Db, id: TokenId) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::api_token::delete(pool, id).await,
        Backend::Postgres(pool) => postgres::api_token::delete(pool, id).await,
        Backend::Sqlite(pool) => sqlite::api_token::delete(pool, id).await,
    }
}
