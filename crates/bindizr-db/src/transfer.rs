use crate::{
    Backend, Db,
    error::DatabaseError,
    model::transfer::{Transfer, TransferWithZone},
    mysql, postgres, sqlite,
};

/// Insert the transfer, or replace the row for its client address and zone.
pub async fn upsert(db: &Db, transfer: Transfer) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::transfer::upsert(pool, transfer).await,
        Backend::Postgres(pool) => postgres::transfer::upsert(pool, transfer).await,
        Backend::Sqlite(pool) => sqlite::transfer::upsert(pool, transfer).await,
    }
}

/// The transfers served to a client address, newest first, with zone names.
pub async fn list_by_client_addr_with_zone(
    db: &Db,
    client_addr: &str,
) -> Result<Vec<TransferWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::transfer::list_by_client_addr_with_zone(pool, client_addr).await
        }
        Backend::Postgres(pool) => {
            postgres::transfer::list_by_client_addr_with_zone(pool, client_addr).await
        }
        Backend::Sqlite(pool) => {
            sqlite::transfer::list_by_client_addr_with_zone(pool, client_addr).await
        }
    }
}

/// The transfer of one zone served to a client address.
pub async fn get_by_client_addr_and_zone_name_with_zone(
    db: &Db,
    client_addr: &str,
    zone_name: &str,
) -> Result<Option<TransferWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::transfer::get_by_client_addr_and_zone_name_with_zone(
                pool,
                client_addr,
                zone_name,
            )
            .await
        }
        Backend::Postgres(pool) => {
            postgres::transfer::get_by_client_addr_and_zone_name_with_zone(
                pool,
                client_addr,
                zone_name,
            )
            .await
        }
        Backend::Sqlite(pool) => {
            sqlite::transfer::get_by_client_addr_and_zone_name_with_zone(
                pool,
                client_addr,
                zone_name,
            )
            .await
        }
    }
}
