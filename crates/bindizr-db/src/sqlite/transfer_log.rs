use bindizr_core::model::transfer::{TransferLog, TransferLogWithZone};
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite};

use crate::error::DatabaseError;
use crate::transfer_log::TransferLogFilter;

/// Append a transfer log row.
pub(crate) async fn create(pool: &Pool<Sqlite>, log: TransferLog) -> Result<(), DatabaseError> {
    let mut connection = pool.acquire().await?;

    sqlx::query(
        r#"
        INSERT INTO transfer_log (client_addr, zone_id, kind, result, transport, incremental, serial, served_at, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&log.client_addr)
    .bind(log.zone_id)
    .bind(log.kind.as_str())
    .bind(log.result.as_str())
    .bind(log.transport.as_str())
    .bind(log.incremental)
    .bind(log.serial)
    .bind(log.served_at)
    .bind(&log.error)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

/// The rows of a client address the filter selects, newest first, with zone names.
pub(crate) async fn list_by_client_addr_and_filter_with_zone(
    pool: &Pool<Sqlite>,
    client_addr: &str,
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let logs = sqlx::query_as::<_, TransferLogWithZone>(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.transport, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE t.client_addr = ?
          AND (? IS NULL OR z.name = ?)
          AND (? IS NULL OR t.served_at >= ?)
          AND (? IS NULL OR t.served_at < ?)
        ORDER BY t.id DESC
        LIMIT ?
        "#,
    )
    .bind(client_addr)
    .bind(filter.zone_name.as_ref())
    .bind(filter.zone_name.as_ref())
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.until)
    .bind(filter.limit.map_or(i64::MAX, i64::from))
    .fetch_all(&mut *connection)
    .await?;

    Ok(logs)
}

/// The newest row of each zone a client address asked for, with zone names.
pub(crate) async fn list_by_client_addr_with_zone_latest_per_zone(
    pool: &Pool<Sqlite>,
    client_addr: &str,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let logs = sqlx::query_as::<_, TransferLogWithZone>(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.transport, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE t.id IN (
            SELECT MAX(id) FROM transfer_log WHERE client_addr = ? GROUP BY zone_id
        )
        ORDER BY t.id DESC
        "#,
    )
    .bind(client_addr)
    .fetch_all(&mut *connection)
    .await?;

    Ok(logs)
}

/// Delete the rows answered before `cutoff`, keeping the newest row of each
/// client address and zone.
pub(crate) async fn prune_older_than(
    pool: &Pool<Sqlite>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = sqlx::query(
        r#"
        DELETE FROM transfer_log
        WHERE served_at < ?
          AND id NOT IN (SELECT MAX(id) FROM transfer_log GROUP BY client_addr, zone_id)
        "#,
    )
    .bind(cutoff)
    .execute(&mut *connection)
    .await?;

    Ok(result.rows_affected())
}
