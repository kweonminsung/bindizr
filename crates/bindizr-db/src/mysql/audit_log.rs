use chrono::{DateTime, Utc};
use sqlx::{MySql, Pool, Transaction};

use crate::{
    audit_log::AuditLogFilter,
    error::DatabaseError,
    model::{audit_log::AuditLog, zone_version::ChangeActor},
};

/// Insert an audit log row in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, MySql>,
    log: AuditLog,
) -> Result<(), DatabaseError> {
    let (changed_by_kind, changed_by_name) =
        log.changed_by.as_ref().map(ChangeActor::as_columns).unzip();
    sqlx::query(
        r#"
        INSERT INTO audit_log (entity, entity_name, operation, change_source, changed_by_kind, changed_by_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(log.entity.as_str())
    .bind(&log.entity_name)
    .bind(log.operation.as_str())
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
    pool: &Pool<MySql>,
    filter: &AuditLogFilter,
) -> Result<Vec<AuditLog>, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let entity = filter.entity.map(|entity| entity.as_str());
    let rows = sqlx::query_as::<_, AuditLog>(
        r#"
        SELECT id, entity, entity_name, operation, change_source, changed_by_kind, changed_by_name, created_at
        FROM audit_log
        WHERE (? IS NULL OR entity = ?)
          AND (? IS NULL OR entity_name = ?)
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at < ?)
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(entity)
    .bind(entity)
    .bind(&filter.entity_name)
    .bind(&filter.entity_name)
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.until)
    .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
    .bind(
        filter
            .offset
            .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
            .unwrap_or(0),
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows)
}

/// How many rows the filter selects.
pub(crate) async fn count_by_filter(
    pool: &Pool<MySql>,
    filter: &AuditLogFilter,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let entity = filter.entity.map(|entity| entity.as_str());
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM audit_log
        WHERE (? IS NULL OR entity = ?)
          AND (? IS NULL OR entity_name = ?)
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at < ?)
        "#,
    )
    .bind(entity)
    .bind(entity)
    .bind(&filter.entity_name)
    .bind(&filter.entity_name)
    .bind(filter.since)
    .bind(filter.since)
    .bind(filter.until)
    .bind(filter.until)
    .fetch_one(&mut *conn)
    .await?;
    Ok(count as u64)
}

/// Delete the rows made before `cutoff`.
pub(crate) async fn prune_older_than(
    pool: &Pool<MySql>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let result = sqlx::query("DELETE FROM audit_log WHERE created_at < ?")
        .bind(cutoff)
        .execute(&mut *conn)
        .await?;
    Ok(result.rows_affected())
}
