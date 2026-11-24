use bindizr_core::model::transfer::{TransferLog, TransferLogWithZone, TransferResult};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::error::DatabaseError;
use crate::transfer_log::TransferLogFilter;

/// Append a transfer log row.
pub(crate) async fn create(pool: &Pool<Postgres>, log: TransferLog) -> Result<(), DatabaseError> {
    let mut connection = pool.acquire().await?;

    sqlx::query(
        r#"
        INSERT INTO transfer_log (client_ip, zone_id, kind, result, transport, incremental, serial, created_at, error_code)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&log.client_ip)
    .bind(log.zone_id)
    .bind(log.kind.as_str())
    .bind(log.result.as_str())
    .bind(log.transport.as_str())
    .bind(log.incremental)
    .bind(log.serial)
    .bind(log.created_at)
    .bind(&log.error_code)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

/// List the rows `filter` selects, in its order, with zone names.
pub(crate) async fn list_by_filter_with_zone(
    pool: &Pool<Postgres>,
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = filter.result.map(TransferResult::as_str);

    let order_by = filter.sort.order_by_sql(filter.order);

    let logs = sqlx::query_as::<_, TransferLogWithZone>(AssertSqlSafe(format!(
        r#"
        SELECT t.client_ip, t.zone_id, t.kind, t.result, t.transport, t.incremental, t.serial, t.created_at, t.error_code, z.name AS zone_name
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE ($1::TEXT[] IS NULL OR t.client_ip = ANY($1))
          AND ($2::TEXT IS NULL OR z.name = $2)
          AND ($3::TEXT IS NULL OR t.result = $3)
          AND ($4::TIMESTAMPTZ IS NULL OR t.created_at >= $4)
          AND ($5::TIMESTAMPTZ IS NULL OR t.created_at < $5)
        {order_by}
        LIMIT $6 OFFSET $7
        "#
    )))
    .bind(&filter.client_ips)
    .bind(&filter.zone_name)
    .bind(result)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.limit.map_or(i64::MAX, i64::from))
    .bind(
        filter
            .offset
            .map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)),
    )
    .fetch_all(&mut *connection)
    .await?;

    Ok(logs)
}

/// Count the rows `filter` selects, its paging aside.
pub(crate) async fn count_by_filter(
    pool: &Pool<Postgres>,
    filter: &TransferLogFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = filter.result.map(TransferResult::as_str);

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE ($1::TEXT[] IS NULL OR t.client_ip = ANY($1))
          AND ($2::TEXT IS NULL OR z.name = $2)
          AND ($3::TEXT IS NULL OR t.result = $3)
          AND ($4::TIMESTAMPTZ IS NULL OR t.created_at >= $4)
          AND ($5::TIMESTAMPTZ IS NULL OR t.created_at < $5)
        "#,
    )
    .bind(&filter.client_ips)
    .bind(&filter.zone_name)
    .bind(result)
    .bind(filter.since)
    .bind(filter.until)
    .fetch_one(&mut *connection)
    .await?;

    Ok(count as u64)
}

/// List the newest row of each zone any of `client_ips` asked for, with
/// zone names: newest by `created_at`, then id, as the listings sort.
pub(crate) async fn list_by_client_ips_with_zone_latest_per_zone(
    pool: &Pool<Postgres>,
    client_ips: &[String],
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let logs = sqlx::query_as::<_, TransferLogWithZone>(
        r#"
        SELECT client_ip, zone_id, kind, result, transport, incremental, serial, created_at, error_code, zone_name
        FROM (
            SELECT t.client_ip, t.zone_id, t.kind, t.result, t.transport, t.incremental, t.serial, t.created_at, t.error_code, z.name AS zone_name, t.id,
                ROW_NUMBER() OVER (PARTITION BY t.zone_id ORDER BY t.created_at DESC, t.id DESC) AS recency
            FROM transfer_log t
            INNER JOIN zones z ON z.id = t.zone_id
            WHERE t.client_ip = ANY($1)
        ) latest
        WHERE recency = 1
        ORDER BY created_at DESC, id DESC
        "#,
    )
    .bind(client_ips)
    .fetch_all(&mut *connection)
    .await?;

    Ok(logs)
}

/// Prune the rows answered before `cutoff`, returning how many. The newest row
/// of each client address and zone stays whatever its age: it is the last
/// transfer the status reports read.
pub(crate) async fn prune_older_than(
    pool: &Pool<Postgres>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = sqlx::query(
        r#"
        DELETE FROM transfer_log
        WHERE created_at < $1
          AND id NOT IN (
              SELECT id FROM (
                  SELECT id, ROW_NUMBER() OVER (
                      PARTITION BY client_ip, zone_id ORDER BY created_at DESC, id DESC
                  ) AS recency
                  FROM transfer_log
              ) AS newest
              WHERE recency = 1
          )
        "#,
    )
    .bind(cutoff)
    .execute(&mut *connection)
    .await?;

    Ok(result.rows_affected())
}
