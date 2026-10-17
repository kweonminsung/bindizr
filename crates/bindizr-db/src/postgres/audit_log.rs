use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres, Transaction};

use crate::{
    audit_log::AuditLogFilter,
    error::DatabaseError,
    model::{audit_log::AuditLog, zone_version::ChangeActor},
};

/// Insert an audit log row in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    log: AuditLog,
) -> Result<(), DatabaseError> {
    let (changed_by_kind, changed_by_name) =
        log.changed_by.as_ref().map(ChangeActor::as_columns).unzip();
    sqlx::query(
        r#"
        INSERT INTO audit_log (entity, entity_name, operation, detail, change_source, changed_by_kind, changed_by_name, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(log.entity.as_str())
    .bind(&log.entity_name)
    .bind(log.operation.as_str())
    .bind(&log.detail)
    .bind(log.change_source.as_str())
    .bind(changed_by_kind)
    .bind(changed_by_name)
    .bind(log.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The rows the filter selects, newest first.
pub(crate) async fn list_by_filter(
    pool: &Pool<Postgres>,
    filter: &AuditLogFilter,
) -> Result<Vec<AuditLog>, DatabaseError> {
    let entity = filter.entity.map(|entity| entity.as_str());
    let order_by = filter.sort.order_by_sql(filter.order);
    let rows = sqlx::query_as::<_, AuditLog>(AssertSqlSafe(format!(
        r#"
        SELECT id, entity, entity_name, operation, detail, change_source, changed_by_kind, changed_by_name, created_at
        FROM audit_log
        WHERE ($1::TEXT IS NULL OR entity = $1)
          AND ($2::TEXT IS NULL OR entity_name = $2)
          AND ($3::TIMESTAMPTZ IS NULL OR created_at >= $3)
          AND ($4::TIMESTAMPTZ IS NULL OR created_at < $4)
        {order_by}
        LIMIT $5 OFFSET $6
        "#
    )))
    .bind(entity)
    .bind(&filter.entity_name)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
    .bind(
        filter
            .offset
            .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
            .unwrap_or(0),
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// How many rows the filter selects.
pub(crate) async fn count_by_filter(
    pool: &Pool<Postgres>,
    filter: &AuditLogFilter,
) -> Result<u64, DatabaseError> {
    let entity = filter.entity.map(|entity| entity.as_str());
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE ($1::TEXT IS NULL OR entity = $1)
          AND ($2::TEXT IS NULL OR entity_name = $2)
          AND ($3::TIMESTAMPTZ IS NULL OR created_at >= $3)
          AND ($4::TIMESTAMPTZ IS NULL OR created_at < $4)
        "#,
    )
    .bind(entity)
    .bind(&filter.entity_name)
    .bind(filter.since)
    .bind(filter.until)
    .fetch_one(pool)
    .await?;
    Ok(count as u64)
}

/// Delete the rows made before `cutoff`.
pub(crate) async fn prune_older_than(
    pool: &Pool<Postgres>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let result = sqlx::query("DELETE FROM audit_log WHERE created_at < $1")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
