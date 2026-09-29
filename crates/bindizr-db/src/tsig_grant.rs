use bindizr_core::model::{tsig_grant::TsigGrantId, tsig_key::TsigKeyId, zone::ZoneId};

use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::tsig_grant::TsigGrant, mysql,
    postgres, sqlite, tx::TransactionKind,
};

/// Insert a TSIG grant.
pub async fn create(db: &Db, grant: TsigGrant) -> Result<TsigGrant, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_grant::create(pool, grant).await,
        Backend::Postgres(pool) => postgres::tsig_grant::create(pool, grant).await,
        Backend::Sqlite(pool) => sqlite::tsig_grant::create(pool, grant).await,
    }
}

/// Find a TSIG grant by ID.
pub async fn get(db: &Db, id: TsigGrantId) -> Result<Option<TsigGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_grant::get(pool, id).await,
        Backend::Postgres(pool) => postgres::tsig_grant::get(pool, id).await,
        Backend::Sqlite(pool) => sqlite::tsig_grant::get(pool, id).await,
    }
}

/// List TSIG grants for a zone.
pub async fn list_by_zone_id(db: &Db, zone_id: ZoneId) -> Result<Vec<TsigGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_grant::list_by_zone_id(pool, zone_id).await,
        Backend::Postgres(pool) => postgres::tsig_grant::list_by_zone_id(pool, zone_id).await,
        Backend::Sqlite(pool) => sqlite::tsig_grant::list_by_zone_id(pool, zone_id).await,
    }
}

/// List TSIG grants for a TSIG key.
pub async fn list_by_key_id(
    db: &Db,
    tsig_key_id: TsigKeyId,
) -> Result<Vec<TsigGrant>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_grant::list_by_key_id(pool, tsig_key_id).await,
        Backend::Postgres(pool) => postgres::tsig_grant::list_by_key_id(pool, tsig_key_id).await,
        Backend::Sqlite(pool) => sqlite::tsig_grant::list_by_key_id(pool, tsig_key_id).await,
    }
}

/// Grants giving `tsig_key_id` rights in `zone_id`, for nsupdate
/// authorization inside the update transaction.
pub async fn list_by_zone_id_and_key_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    tsig_key_id: TsigKeyId,
    lock_level: LockLevel,
) -> Result<Vec<TsigGrant>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::tsig_grant::list_by_zone_id_and_key_id_tx(tx, zone_id, tsig_key_id, lock_level)
                .await
        }
        TransactionKind::Postgres(tx) => {
            postgres::tsig_grant::list_by_zone_id_and_key_id_tx(
                tx,
                zone_id,
                tsig_key_id,
                lock_level,
            )
            .await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::tsig_grant::list_by_zone_id_and_key_id_tx(tx, zone_id, tsig_key_id, lock_level)
                .await
        }
    }
}

/// Count TSIG grants for a TSIG key.
pub async fn count_by_key_id(db: &Db, tsig_key_id: TsigKeyId) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_grant::count_by_key_id(pool, tsig_key_id).await,
        Backend::Postgres(pool) => postgres::tsig_grant::count_by_key_id(pool, tsig_key_id).await,
        Backend::Sqlite(pool) => sqlite::tsig_grant::count_by_key_id(pool, tsig_key_id).await,
    }
}

/// Delete a TSIG grant by ID.
pub async fn delete(db: &Db, id: TsigGrantId) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::tsig_grant::delete(pool, id).await,
        Backend::Postgres(pool) => postgres::tsig_grant::delete(pool, id).await,
        Backend::Sqlite(pool) => sqlite::tsig_grant::delete(pool, id).await,
    }
}

/// Delete every grant a TSIG key holds in one zone, returning how many
/// rows went. One statement, so a revocation never lands half-applied.
pub async fn delete_by_key_id_and_zone_id(
    db: &Db,
    tsig_key_id: TsigKeyId,
    zone_id: ZoneId,
) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::tsig_grant::delete_by_key_id_and_zone_id(pool, tsig_key_id, zone_id).await
        }
        Backend::Postgres(pool) => {
            postgres::tsig_grant::delete_by_key_id_and_zone_id(pool, tsig_key_id, zone_id).await
        }
        Backend::Sqlite(pool) => {
            sqlite::tsig_grant::delete_by_key_id_and_zone_id(pool, tsig_key_id, zone_id).await
        }
    }
}
