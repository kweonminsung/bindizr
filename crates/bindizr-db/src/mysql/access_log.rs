use bindizr_core::model::access_log::{AccessLog, AccessResult, AccessSource};
use bindizr_core::model::change::ChangeActor;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::access_log::AccessLogFilter;
use crate::error::DatabaseError;

/// Append an access log row.
pub(crate) async fn create(pool: &Pool<MySql>, log: &AccessLog) -> Result<(), DatabaseError> {
    let mut connection = pool.acquire().await?;

    let (caller_kind, caller_name) = log.caller.as_ref().map(ChangeActor::as_columns).unzip();

    sqlx::query(
        r#"
        INSERT INTO access_log (source, client_addr, method, target, status, result, caller_kind, caller_name, error, requested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(log.source.as_str())
    .bind(&log.client_addr)
    .bind(&log.method)
    .bind(&log.target)
    .bind(&log.status)
    .bind(log.result.as_str())
    .bind(caller_kind)
    .bind(caller_name)
    .bind(&log.error)
    .bind(log.requested_at)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

/// List the rows `filter` selects, in its order.
pub(crate) async fn list_by_filter(
    pool: &Pool<MySql>,
    filter: &AccessLogFilter,
) -> Result<Vec<AccessLog>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let source = filter.source.map(AccessSource::as_str);
    let result = filter.result.map(AccessResult::as_str);

    let order_by = filter.sort.order_by_sql(filter.order);

    let logs = sqlx::query_as::<_, AccessLog>(AssertSqlSafe(format!(
        r#"
        SELECT source, client_addr, method, target, status, result,
               caller_kind AS changed_by_kind, caller_name AS changed_by_name, error, requested_at
        FROM access_log
        WHERE (? IS NULL OR source = ?)
          AND (? IS NULL OR result = ?)
          AND (? IS NULL OR caller_name = ?)
          AND (? IS NULL OR client_addr = ?)
          AND (? IS NULL OR requested_at >= ?)
          AND (? IS NULL OR requested_at < ?)
        {order_by}
        LIMIT ? OFFSET ?
        "#
    )))
    .bind(source)
    .bind(source)
    .bind(result)
    .bind(result)
    .bind(&filter.caller_name)
    .bind(&filter.caller_name)
    .bind(&filter.client_addr)
    .bind(&filter.client_addr)
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
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
    pool: &Pool<MySql>,
    filter: &AccessLogFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let source = filter.source.map(AccessSource::as_str);
    let result = filter.result.map(AccessResult::as_str);

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM access_log
        WHERE (? IS NULL OR source = ?)
          AND (? IS NULL OR result = ?)
          AND (? IS NULL OR caller_name = ?)
          AND (? IS NULL OR client_addr = ?)
          AND (? IS NULL OR requested_at >= ?)
          AND (? IS NULL OR requested_at < ?)
        "#,
    )
    .bind(source)
    .bind(source)
    .bind(result)
    .bind(result)
    .bind(&filter.caller_name)
    .bind(&filter.caller_name)
    .bind(&filter.client_addr)
    .bind(&filter.client_addr)
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.until)
    .fetch_one(&mut *connection)
    .await?;

    Ok(count as u64)
}

/// Prune the rows made before `cutoff`, returning how many.
pub(crate) async fn prune_older_than(
    pool: &Pool<MySql>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = sqlx::query("DELETE FROM access_log WHERE requested_at < ?")
        .bind(cutoff)
        .execute(&mut *connection)
        .await?;

    Ok(result.rows_affected())
}
