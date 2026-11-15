use bindizr_core::model::transfer::{TransferLog, TransferLogWithZone, TransferResult};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::error::DatabaseError;
use crate::sql;
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

/// List the rows `filter` selects, newest first, with zone names.
pub(crate) async fn list_by_filter_with_zone(
    pool: &Pool<Sqlite>,
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let client_addrs = filter.client_addrs.as_deref().unwrap_or_default();
    // An empty address list selects nothing; `IN ()` is not valid SQL.
    let client_addr_clause = match &filter.client_addrs {
        Some(client_addrs) if client_addrs.is_empty() => "AND 1 = 0".to_string(),
        Some(client_addrs) => format!(
            "AND t.client_addr IN ({})",
            sql::placeholders(client_addrs.len())
        ),
        None => String::new(),
    };
    let result = filter.result.map(TransferResult::as_str);

    let mut query = sqlx::query_as::<_, TransferLogWithZone>(AssertSqlSafe(format!(
        r#"
        SELECT t.client_addr, t.kind, t.result, t.transport, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE (? IS NULL OR z.name = ?)
          AND (? IS NULL OR t.result = ?)
          AND (? IS NULL OR t.served_at >= ?)
          AND (? IS NULL OR t.served_at < ?)
          {client_addr_clause}
        ORDER BY t.id DESC
        LIMIT ? OFFSET ?
        "#
    )))
    .bind(&filter.zone_name)
    .bind(&filter.zone_name)
    .bind(result)
    .bind(result)
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.until);

    for client_addr in client_addrs {
        query = query.bind(client_addr);
    }

    let logs = query
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
    pool: &Pool<Sqlite>,
    filter: &TransferLogFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let client_addrs = filter.client_addrs.as_deref().unwrap_or_default();
    // An empty address list selects nothing; `IN ()` is not valid SQL.
    let client_addr_clause = match &filter.client_addrs {
        Some(client_addrs) if client_addrs.is_empty() => "AND 1 = 0".to_string(),
        Some(client_addrs) => format!(
            "AND t.client_addr IN ({})",
            sql::placeholders(client_addrs.len())
        ),
        None => String::new(),
    };
    let result = filter.result.map(TransferResult::as_str);

    let mut query = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
        r#"
        SELECT COUNT(*)
        FROM transfer_log t
        INNER JOIN zones z ON z.id = t.zone_id
        WHERE (? IS NULL OR z.name = ?)
          AND (? IS NULL OR t.result = ?)
          AND (? IS NULL OR t.served_at >= ?)
          AND (? IS NULL OR t.served_at < ?)
          {client_addr_clause}
        "#
    )))
    .bind(&filter.zone_name)
    .bind(&filter.zone_name)
    .bind(result)
    .bind(result)
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.until);

    for client_addr in client_addrs {
        query = query.bind(client_addr);
    }

    let count = query.fetch_one(&mut *connection).await?;

    Ok(count as u64)
}

/// List the newest row of each zone a client address asked for, with zone
/// names.
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

/// Prune the rows answered before `cutoff`, returning how many. The newest row
/// of each client address and zone stays whatever its age: it is the last
/// transfer the status reports read.
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
