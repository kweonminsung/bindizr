use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Sqlite, Transaction};

use crate::{LockLevel, error::DatabaseError, model::zone_change::ZoneChange};

/// Insert a batch of journal entries in the current transaction.
pub(crate) async fn create_many_tx(
    tx: &mut Transaction<'_, Sqlite>,
    changes: &[ZoneChange],
) -> Result<(), DatabaseError> {
    // One journal row per record, so size it like the record insert:
    // 11 binds per row, leaving room under SQLite's 32766 limit.
    const CHUNK: usize = 400;
    const ROW: &str = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    for chunk in changes.chunks(CHUNK) {
        let mut sql = String::from(
            "INSERT INTO zone_journal (zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived, created_at) VALUES ",
        );
        for i in 0..chunk.len() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(ROW);
        }

        let now = Utc::now();
        let mut query = sqlx::query(AssertSqlSafe(sql));
        for c in chunk {
            query = query
                .bind(c.zone_id)
                .bind(c.serial)
                .bind(c.operation)
                .bind(&c.record_name)
                .bind(c.record_type.clone())
                .bind(c.record_value.clone())
                .bind(c.record_rdata.clone())
                .bind(c.record_ttl)
                .bind(c.record_priority)
                .bind(c.derived)
                .bind(now);
        }
        query
            .execute(&mut **tx)
            .await
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
    }
    Ok(())
}

/// List journal entries in the interval `(from_serial, to_serial]`.
pub(crate) async fn list_between_serials(
    pool: &Pool<Sqlite>,
    zone_id: i32,
    from_serial: i32,
    to_serial: i32,
) -> Result<Vec<ZoneChange>, DatabaseError> {
    sqlx::query_as::<_, ZoneChange>(
        r#"
        SELECT zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived
        FROM zone_journal
        WHERE zone_id = ? AND serial > ? AND serial <= ?
        ORDER BY serial, id
        "#
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_all(pool)
    .await
    .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
}

/// Count journal entries in the interval `(from_serial, to_serial]`.
pub(crate) async fn count_between_serials(
    pool: &Pool<Sqlite>,
    zone_id: i32,
    from_serial: i32,
    to_serial: i32,
) -> Result<u64, DatabaseError> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM zone_journal
        WHERE zone_id = ? AND serial > ? AND serial <= ?
        "#,
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_one(pool)
    .await
    .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

    Ok(count as u64)
}

/// List journal entries in the interval `(from_serial, to_serial]` in the current
/// transaction.
pub(crate) async fn list_between_serials_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
    from_serial: i32,
    to_serial: i32,
    _lock_level: LockLevel,
) -> Result<Vec<ZoneChange>, DatabaseError> {
    sqlx::query_as::<_, ZoneChange>(
        r#"
        SELECT zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived
        FROM zone_journal
        WHERE zone_id = ? AND serial > ? AND serial <= ?
        ORDER BY serial, id
        "#
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
}

/// Prune one zone's journal rows older than `cutoff` in the current transaction.
pub(crate) async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<u64, DatabaseError> {
    // Delete whole serials only: everything up to the highest serial with
    // a row older than the cutoff, so remaining IXFR steps stay complete.
    // SQLite compares timestamps as text; sqlx's RFC 3339 sorts
    // chronologically.
    let result = sqlx::query(
        r#"
        DELETE FROM zone_journal
        WHERE zone_id = ?
          AND serial <= (
              SELECT MAX(serial) FROM zone_journal
              WHERE zone_id = ? AND created_at < ?
          )
        "#,
    )
    .bind(zone_id)
    .bind(zone_id)
    .bind(cutoff)
    .execute(&mut **tx)
    .await
    .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

    Ok(result.rows_affected())
}
