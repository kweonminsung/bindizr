use bindizr_core::dns::Serial;
use bindizr_core::model::zone::ZoneId;
use bindizr_core::model::zone_change::ZoneChange;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Postgres, Transaction};

use crate::error::DatabaseError;

/// Insert many zone changes in one statement (chunked). Ids are not returned.
pub(crate) async fn create_many_tx(
    tx: &mut Transaction<'_, Postgres>,
    changes: &[ZoneChange],
) -> Result<(), DatabaseError> {
    const CHUNK: usize = 500;

    for chunk in changes.chunks(CHUNK) {
        let mut sql = String::from(
            "INSERT INTO zone_journal (zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived, created_at) VALUES ",
        );
        let mut bind_index = 1;

        for i in 0..chunk.len() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(&format!(
                "(${bind_index}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                bind_index + 1,
                bind_index + 2,
                bind_index + 3,
                bind_index + 4,
                bind_index + 5,
                bind_index + 6,
                bind_index + 7,
                bind_index + 8,
                bind_index + 9,
                bind_index + 10,
            ));
            bind_index += 11;
        }

        let now = Utc::now();
        let mut query = sqlx::query(AssertSqlSafe(sql));

        for change in chunk {
            query = query
                .bind(change.zone_id)
                .bind(change.serial)
                .bind(change.operation)
                .bind(&change.record_name)
                .bind(&change.record_type)
                .bind(&change.record_value)
                .bind(&change.record_rdata)
                .bind(change.record_ttl)
                .bind(change.record_priority)
                .bind(change.record_type.is_derived())
                .bind(now);
        }

        query.execute(&mut **tx).await?;
    }

    Ok(())
}

/// Count the rows `list_between_serials_tx` would return, so a caller can weigh
/// the delta before loading it.
pub(crate) async fn count_between_serials_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<u64, DatabaseError> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM zone_journal
        WHERE zone_id = $1 AND ((serial > $2 AND serial <= $3) OR ($2 > $3 AND (serial > $2 OR serial <= $3)))
        "#,
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_one(&mut **tx)
    .await?;

    Ok(count as u64)
}

/// List journal entries in `(from_serial, to_serial]` consistently with
/// mutations in the current transaction.
pub(crate) async fn list_between_serials_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneChange>, DatabaseError> {
    let changes = sqlx::query_as::<_, ZoneChange>(
        r#"
        SELECT zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority
        FROM zone_journal
        WHERE zone_id = $1 AND ((serial > $2 AND serial <= $3) OR ($2 > $3 AND (serial > $2 OR serial <= $3)))
        ORDER BY id
        "#,
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_all(&mut **tx)
    .await?;

    Ok(changes)
}

/// Prune expired whole serials, retaining a contiguous IXFR chain. Older
/// requests use AXFR; return the deleted row count.
pub(crate) async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    // Delete whole serials only, so the remaining IXFR steps stay complete.
    let result = sqlx::query(
        r#"
        DELETE FROM zone_journal
        WHERE zone_id = $1
          AND serial IN (
              SELECT serial FROM zone_journal WHERE zone_id = $1
              GROUP BY serial HAVING MAX(created_at) < $2
          )
        "#,
    )
    .bind(zone_id)
    .bind(cutoff)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}

/// Prune history outside the unambiguous RFC 1982 half-range behind the current serial.
pub(crate) async fn prune_by_zone_id_outside_serial_window_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    current: Serial,
) -> Result<u64, DatabaseError> {
    let result = sqlx::query(
        "DELETE FROM zone_journal WHERE zone_id = $1 AND (($2 - serial + 4294967296) % 4294967296) >= 2147483648",
    )
    .bind(zone_id)
    .bind(current)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}
