use bindizr_core::dns::name::ZoneName;
use sqlx::{Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::transfer::{Transfer, TransferWithZone},
};

/// Insert the transfer, or replace the row for its client address and zone.
pub(crate) async fn upsert(pool: &Pool<Sqlite>, transfer: Transfer) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query(
        r#"
        INSERT INTO transfers (client_addr, zone_id, kind, result, incremental, serial, served_at, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_addr, zone_id)
        DO UPDATE SET
            kind = excluded.kind,
            result = excluded.result,
            incremental = excluded.incremental,
            serial = excluded.serial,
            served_at = excluded.served_at,
            error = excluded.error
        "#,
    )
    .bind(&transfer.client_addr)
    .bind(transfer.zone_id)
    .bind(transfer.kind.as_str())
    .bind(transfer.result.as_str())
    .bind(transfer.incremental)
    .bind(transfer.serial)
    .bind(transfer.served_at)
    .bind(&transfer.error)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// The transfers served to a client address, newest first, with zone names.
pub(crate) async fn list_by_client_addr_with_zone(
    pool: &Pool<Sqlite>,
    client_addr: &str,
) -> Result<Vec<TransferWithZone>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let transfers = sqlx::query_as::<_, TransferWithZone>(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfers t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE t.client_addr = ?
        ORDER BY t.served_at DESC
        "#,
    )
    .bind(client_addr)
    .fetch_all(&mut *conn)
    .await?;

    Ok(transfers)
}

/// The transfer of one zone served to a client address.
pub(crate) async fn get_by_client_addr_and_zone_name_with_zone(
    pool: &Pool<Sqlite>,
    client_addr: &str,
    zone_name: &ZoneName,
) -> Result<Option<TransferWithZone>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let transfer = sqlx::query_as::<_, TransferWithZone>(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfers t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE t.client_addr = ? AND z.name = ?
        "#,
    )
    .bind(client_addr)
    .bind(zone_name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(transfer)
}
