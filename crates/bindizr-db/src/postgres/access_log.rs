use bindizr_core::model::access_log::{AccessLog, AccessResult, AccessSource};
use bindizr_core::model::change::ChangeActor;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};

use crate::access_log::AccessLogFilter;
use crate::error::DatabaseError;

/// Append an access log row.
pub(crate) async fn create(pool: &Pool<Postgres>, log: &AccessLog) -> Result<(), DatabaseError> {
    let mut connection = pool.acquire().await?;

    let (caller_kind, caller_name) = log.caller.as_ref().map(ChangeActor::as_columns).unzip();

    sqlx::query(
        r#"
        INSERT INTO access_log (source, client_addr, method, target, status, result, caller_kind, caller_name, error, requested_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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

/// List the rows `filter` selects, newest first.
pub(crate) async fn list_by_filter(
    pool: &Pool<Postgres>,
    filter: &AccessLogFilter,
) -> Result<Vec<AccessLog>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let source = filter.source.map(AccessSource::as_str);
    let result = filter.result.map(AccessResult::as_str);

    let logs = sqlx::query_as::<_, AccessLog>(
        r#"
        SELECT source, client_addr, method, target, status, result,
               caller_kind AS changed_by_kind, caller_name AS changed_by_name, error, requested_at
        FROM access_log
        WHERE ($1::TEXT IS NULL OR source = $1)
          AND ($2::TEXT IS NULL OR result = $2)
          AND ($3::TEXT IS NULL OR caller_name = $3)
          AND ($4::TEXT IS NULL OR client_addr = $4)
          AND ($5::TIMESTAMPTZ IS NULL OR requested_at >= $5)
          AND ($6::TIMESTAMPTZ IS NULL OR requested_at < $6)
        ORDER BY id DESC
        LIMIT $7 OFFSET $8
        "#,
    )
    .bind(source)
    .bind(result)
    .bind(&filter.caller_name)
    .bind(&filter.client_addr)
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
    filter: &AccessLogFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let source = filter.source.map(AccessSource::as_str);
    let result = filter.result.map(AccessResult::as_str);

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM access_log
        WHERE ($1::TEXT IS NULL OR source = $1)
          AND ($2::TEXT IS NULL OR result = $2)
          AND ($3::TEXT IS NULL OR caller_name = $3)
          AND ($4::TEXT IS NULL OR client_addr = $4)
          AND ($5::TIMESTAMPTZ IS NULL OR requested_at >= $5)
          AND ($6::TIMESTAMPTZ IS NULL OR requested_at < $6)
        "#,
    )
    .bind(source)
    .bind(result)
    .bind(&filter.caller_name)
    .bind(&filter.client_addr)
    .bind(filter.since)
    .bind(filter.until)
    .fetch_one(&mut *connection)
    .await?;

    Ok(count as u64)
}

/// Prune the rows made before `cutoff`, returning how many.
pub(crate) async fn prune_older_than(
    pool: &Pool<Postgres>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = sqlx::query("DELETE FROM access_log WHERE requested_at < $1")
        .bind(cutoff)
        .execute(&mut *connection)
        .await?;

    Ok(result.rows_affected())
}
