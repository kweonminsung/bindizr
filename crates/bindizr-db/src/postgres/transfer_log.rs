use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};

use crate::error::DatabaseError;
use crate::model::transfer::{TransferLog, TransferLogWithZone};
use crate::transfer_log::TransferLogFilter;

/// Append a transfer log row.
pub(crate) async fn create(pool: &Pool<Postgres>, log: TransferLog) -> Result<(), DatabaseError> {
    let mut connection = pool.acquire().await?;

    sqlx::query(
        r#"
        INSERT INTO transfer_log (client_addr, zone_id, kind, result, transport, incremental, serial, served_at, error)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
    pool: &Pool<Postgres>,
    client_addr: &str,
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let logs = sqlx::query_as::<_, TransferLogWithZone>(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.transport, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE t.client_addr = $1
          AND ($2::TEXT IS NULL OR z.name = $2)
          AND ($3::TIMESTAMPTZ IS NULL OR t.served_at >= $3)
          AND ($4::TIMESTAMPTZ IS NULL OR t.served_at < $4)
        ORDER BY t.id DESC
        LIMIT $5
        "#,
    )
    .bind(client_addr)
    .bind(filter.zone_name.as_ref())
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
    .fetch_all(&mut *connection)
    .await?;

    Ok(logs)
}

/// The newest row of each zone a client address asked for, with zone names.
pub(crate) async fn list_by_client_addr_with_zone_latest_per_zone(
    pool: &Pool<Postgres>,
    client_addr: &str,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let logs = sqlx::query_as::<_, TransferLogWithZone>(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.transport, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE t.id IN (
            SELECT MAX(id) FROM transfer_log WHERE client_addr = $1 GROUP BY zone_id
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
    pool: &Pool<Postgres>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = sqlx::query(
        r#"
        DELETE FROM transfer_log
        WHERE served_at < $1
          AND id NOT IN (SELECT MAX(id) FROM transfer_log GROUP BY client_addr, zone_id)
        "#,
    )
    .bind(cutoff)
    .execute(&mut *connection)
    .await?;

    Ok(result.rows_affected())
}
