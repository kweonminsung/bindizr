use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::token_grant::TokenGrant,
    mysql, postgres, sqlite, tx::TransactionKind,
};

/// Insert a token grant.
pub async fn create(db: &Db, grant: TokenGrant) -> Result<TokenGrant, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::token_grant::create(pool, grant).await,
        Backend::Postgres(pool) => postgres::token_grant::create(pool, grant).await,
        Backend::Sqlite(pool) => sqlite::token_grant::create(pool, grant).await,
    }
}

/// Find a token grant by ID.
pub async fn get(db: &Db, id: i32) -> Result<Option<TokenGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::token_grant::get(pool, id).await,
        Backend::Postgres(pool) => postgres::token_grant::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::token_grant::get(pool, id).await,
    }
}

/// List token grants for a zone.
pub async fn list_by_zone_id(db: &Db, zone_id: i32) -> Result<Vec<TokenGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::token_grant::list_by_zone_id(pool, zone_id).await,
        Backend::Postgres(pool) => postgres::token_grant::list_by_zone_id(pool, zone_id).await,
        Backend::Sqlite(pool) => sqlite::token_grant::list_by_zone_id(pool, zone_id).await,
    }
}

/// Grants giving `api_token_id` rights in `zone_id`, for write
/// authorization inside the caller's transaction.
pub async fn list_by_zone_id_and_token_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
    api_token_id: i32,
    lock_level: LockLevel,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::token_grant::list_by_zone_id_and_token_id_tx(
                tx,
                zone_id,
                api_token_id,
                lock_level,
            )
            .await
        }
        TransactionKind::Postgres(tx) => {
            postgres::token_grant::list_by_zone_id_and_token_id_tx(
                tx,
                zone_id,
                api_token_id,
                lock_level,
            )
            .await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::token_grant::list_by_zone_id_and_token_id_tx(
                tx,
                zone_id,
                api_token_id,
                lock_level,
            )
            .await
        }
    }
}

/// Every grant of `api_token_id`; drives what a scoped token can see and
/// NOTIFY.
pub async fn list_by_token_id(
    db: &Db,
    api_token_id: i32,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::token_grant::list_by_token_id(pool, api_token_id).await,
        Backend::Postgres(pool) => {
            postgres::token_grant::list_by_token_id(pool, api_token_id).await
        }
        Backend::Sqlite(pool) => sqlite::token_grant::list_by_token_id(pool, api_token_id).await,
    }
}

/// Delete a token grant by ID.
pub async fn delete(db: &Db, id: i32) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::token_grant::delete(pool, id).await,
        Backend::Postgres(pool) => postgres::token_grant::delete(pool, id).await,
        Backend::Sqlite(pool) => sqlite::token_grant::delete(pool, id).await,
    }
}

/// Delete every grant a token holds in one zone, returning how many rows
/// went. One statement, so a revocation never lands half-applied.
pub async fn delete_by_token_id_and_zone_id(
    db: &Db,
    api_token_id: i32,
    zone_id: i32,
) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::token_grant::delete_by_token_id_and_zone_id(pool, api_token_id, zone_id).await
        }
        Backend::Postgres(pool) => {
            postgres::token_grant::delete_by_token_id_and_zone_id(pool, api_token_id, zone_id).await
        }
        Backend::Sqlite(pool) => {
            sqlite::token_grant::delete_by_token_id_and_zone_id(pool, api_token_id, zone_id).await
        }
    }
}
