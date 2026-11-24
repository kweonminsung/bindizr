use bindizr_core::model::activity_log::ActivityLog;
use bindizr_core::model::change::ChangeActor;
use chrono::{DateTime, Utc};
use sqlx::{Pool, QueryBuilder, Sqlite, Transaction};

use crate::activity_log::ActivityLogFilter;
use crate::error::DatabaseError;

/// Insert one activity log row, assigning its id in the caller's transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    log: &ActivityLog,
) -> Result<(), DatabaseError> {
    create_many_tx(tx, std::slice::from_ref(log)).await
}

/// Insert the batch in input order.
pub(crate) async fn create_many_tx(
    tx: &mut Transaction<'_, Sqlite>,
    logs: &[ActivityLog],
) -> Result<(), DatabaseError> {
    // Bound each statement to 6000 parameters.
    const CHUNK: usize = 500;

    for chunk in logs.chunks(CHUNK) {
        let mut query = QueryBuilder::<Sqlite>::new(
            r#"
            INSERT INTO activity_log (
                operation, result, target_name, zone_name, record_id,
                record_name, record_type, source, actor_kind, actor_name, created_at, detail
            )
            "#,
        );
        query.push_values(chunk, |mut row, log| {
            let (actor_kind, actor_name) = log.actor.as_ref().map(ChangeActor::as_columns).unzip();
            row.push_bind(log.operation.as_str())
                .push_bind(log.result.as_str())
                .push_bind(&log.target.name)
                .push_bind(&log.target.zone_name)
                .push_bind(log.target.record_id)
                .push_bind(&log.target.record_name)
                .push_bind(&log.target.record_type)
                .push_bind(log.source.as_str())
                .push_bind(actor_kind)
                .push_bind(actor_name)
                .push_bind(log.created_at)
                .push_bind(&log.detail);
        });

        query.build().execute(&mut **tx).await?;
    }

    Ok(())
}

/// List activity rows matching the filter, using the requested order.
pub(crate) async fn list_by_filter(
    pool: &Pool<Sqlite>,
    filter: &ActivityLogFilter,
) -> Result<Vec<ActivityLog>, DatabaseError> {
    let mut query = QueryBuilder::<Sqlite>::new(
        r#"
        SELECT id, operation, result, target_name, zone_name, record_id,
               record_name, record_type, source, actor_kind, actor_name,
               created_at, detail
        FROM activity_log
        WHERE TRUE
        "#,
    );
    push_filters(&mut query, filter);
    query
        .push(" ")
        .push(filter.sort.order_by_sql(filter.order))
        .push(" LIMIT ")
        .push_bind(filter.limit.map_or(i64::MAX, i64::from))
        .push(" OFFSET ")
        .push_bind(
            filter
                .offset
                .map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)),
        );

    Ok(query.build_query_as().fetch_all(pool).await?)
}

/// Count all matches without paging.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    filter: &ActivityLogFilter,
) -> Result<u64, DatabaseError> {
    let mut query = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM activity_log WHERE TRUE");
    push_filters(&mut query, filter);
    Ok(query.build_query_scalar::<i64>().fetch_one(pool).await? as u64)
}

/// Add the same filter predicates to listing and count statements.
fn push_filters(query: &mut QueryBuilder<Sqlite>, filter: &ActivityLogFilter) {
    if let Some(entity) = &filter.entity {
        let prefix = format!("{entity}.");
        query
            .push(" AND SUBSTR(operation, 1, ")
            .push_bind(i32::try_from(prefix.len()).unwrap_or(i32::MAX))
            .push(") = ")
            .push_bind(prefix);
    }
    if let Some(operation) = filter.operation {
        query
            .push(" AND operation = ")
            .push_bind(operation.as_str());
    }
    if let Some(result) = filter.result {
        query.push(" AND result = ").push_bind(result.as_str());
    }
    if let Some(name) = &filter.name {
        query
            .push(" AND (target_name = ")
            .push_bind(name)
            .push(" OR zone_name = ")
            .push_bind(name)
            .push(")");
    }
    if let Some(zone_name) = &filter.zone_name {
        query.push(" AND zone_name = ").push_bind(zone_name);
    }
    if let Some(record_name) = &filter.record_name {
        query.push(" AND record_name = ").push_bind(record_name);
    }
    if let Some(record_type) = &filter.record_type {
        query.push(" AND record_type = ").push_bind(record_type);
    }
    if let Some(since) = filter.since {
        query.push(" AND created_at >= ").push_bind(since);
    }
    if let Some(until) = filter.until {
        query.push(" AND created_at < ").push_bind(until);
    }
}

/// Prune activity log rows before the cutoff.
pub(crate) async fn prune_older_than(
    pool: &Pool<Sqlite>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let result = sqlx::query("DELETE FROM activity_log WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
