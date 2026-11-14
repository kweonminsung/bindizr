use bindizr_core::model::audit_log::{AuditEntity, AuditLog};
use bindizr_core::model::change::ChangeActor;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, MySql, Pool, Transaction};

use crate::audit_log::AuditLogFilter;
use crate::error::DatabaseError;

/// Insert an audit log row in the current transaction, the change's own.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, MySql>,
    log: AuditLog,
) -> Result<(), DatabaseError> {
    let (changed_by_kind, changed_by_name) =
        log.changed_by.as_ref().map(ChangeActor::as_columns).unzip();

    sqlx::query(
        r#"
        INSERT INTO audit_log (entity, entity_name, operation, detail, change_source, changed_by_kind, changed_by_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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

/// List the rows `filter` selects, in its order.
pub(crate) async fn list_by_filter(
    pool: &Pool<MySql>,
    filter: &AuditLogFilter,
) -> Result<Vec<AuditLog>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let entity = filter.entity.map(AuditEntity::as_str);
    let order_by = filter.sort.order_by_sql(filter.order);

    let logs = sqlx::query_as::<_, AuditLog>(AssertSqlSafe(format!(
        r#"
        SELECT id, entity, entity_name, operation, detail, change_source, changed_by_kind, changed_by_name, created_at
        FROM audit_log
        WHERE (? IS NULL OR entity = ?)
          AND (? IS NULL OR entity_name = ?)
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at < ?)
        {order_by}
        LIMIT ? OFFSET ?
        "#
    )))
    .bind(entity)
    .bind(entity)
    .bind(&filter.entity_name)
    .bind(&filter.entity_name)
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
    filter: &AuditLogFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let entity = filter.entity.map(AuditEntity::as_str);

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

    let result = sqlx::query("DELETE FROM audit_log WHERE created_at < ?")
        .bind(cutoff)
        .execute(&mut *connection)
        .await?;

    Ok(result.rows_affected())
}
