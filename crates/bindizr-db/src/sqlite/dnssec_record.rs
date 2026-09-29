use bindizr_core::model::{dnssec_record::DnssecRecordId, zone::ZoneId};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Sqlite, Transaction};

use crate::{
    LockLevel,
    dnssec_record::DnssecRecordFilter,
    error::DatabaseError,
    model::dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    sql::{apex_owner_sql, concat_pipes, grant_record_match_sql, like_pattern, refresh_bound},
};

/// Insert a batch of derived DNSSEC records in the current transaction.
pub(crate) async fn create_many_tx(
    tx: &mut Transaction<'_, Sqlite>,
    records: &[DnssecRecord],
) -> Result<(), DatabaseError> {
    // 8 columns per row; keep bind count under SQLite's conservative limit.
    const CHUNK: usize = 100;
    const ROW: &str = "(?, ?, ?, ?, ?, ?, ?, ?)";
    for chunk in records.chunks(CHUNK) {
        let mut sql = String::from(
            "INSERT INTO dnssec_records (zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, record_set_digest) VALUES ",
        );
        for i in 0..chunk.len() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str(ROW);
        }

        let mut query = sqlx::query(AssertSqlSafe(sql));
        for r in chunk {
            query = query
                .bind(r.zone_id)
                .bind(&r.name)
                .bind(r.record_type)
                .bind(r.covered_record_type)
                .bind(r.ttl)
                .bind(r.rdata.clone())
                .bind(r.expires_at)
                .bind(r.record_set_digest.clone());
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

/// List derived DNSSEC records for a zone in the current transaction.
pub(crate) async fn list_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    _lock_level: LockLevel,
) -> Result<Vec<DnssecRecord>, DatabaseError> {
    let records = sqlx::query_as::<_, DnssecRecord>(
        r#"
        SELECT id, zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, record_set_digest
        FROM dnssec_records
        WHERE zone_id = ?
        ORDER BY id
        "#,
    )
    .bind(zone_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(records)
}

/// Delete the derived DNSSEC records with the supplied IDs in the current transaction.
pub(crate) async fn delete_many_tx(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[DnssecRecordId],
) -> Result<(), DatabaseError> {
    if ids.is_empty() {
        return Ok(());
    }
    // One bind per id; keep the count under SQLite's conservative limit.
    const CHUNK: usize = 900;
    for chunk in ids.chunks(CHUNK) {
        let mut sql = String::from("DELETE FROM dnssec_records WHERE id IN (");
        for i in 0..chunk.len() {
            sql.push_str(if i == 0 { "?" } else { ",?" });
        }
        sql.push(')');

        let mut query = sqlx::query(AssertSqlSafe(sql));
        for id in chunk {
            query = query.bind(id);
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

/// Delete all derived DNSSEC records for a zone in the current transaction.
pub(crate) async fn delete_by_zone_id_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM dnssec_records WHERE zone_id = ?")
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Count zones with stored derived DNSSEC records.
pub(crate) async fn count_zone_ids(pool: &Pool<Sqlite>) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(DISTINCT zone_id) FROM dnssec_records")
        .fetch_one(&mut *conn)
        .await?;

    Ok(count as u64)
}

/// List zones with signatures due for renewal.
pub(crate) async fn list_zone_ids_expiring_within_refresh(
    pool: &Pool<Sqlite>,
    cutoff: DateTime<Utc>,
) -> Result<Vec<ZoneId>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    // The per-policy threshold is no constant, so nothing can seek the
    // index; this widest-window bound is, and the comparison below refines it.
    let Some(max_refresh_days) = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT MAX(signature_refresh_days) FROM dnssec_policies",
    )
    .fetch_one(&mut *conn)
    .await?
    else {
        return Ok(Vec::new());
    };
    let bound = refresh_bound(cutoff, max_refresh_days);

    let zone_ids = sqlx::query_scalar::<_, ZoneId>(
        r#"
        SELECT DISTINCT r.zone_id
        FROM dnssec_records r
        JOIN zones z ON z.id = r.zone_id
        JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
        WHERE r.expires_at IS NOT NULL
          AND r.expires_at < ?
          AND datetime(r.expires_at) < datetime(?, '+' || p.signature_refresh_days || ' days')
        "#,
    )
    .bind(bound)
    .bind(cutoff)
    .fetch_all(&mut *conn)
    .await?;

    Ok(zone_ids)
}

/// Count signatures due for renewal.
pub(crate) async fn count_expiring_within_refresh(
    pool: &Pool<Sqlite>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    // The per-policy threshold is no constant, so nothing can seek the
    // index; this widest-window bound is, and the comparison below refines it.
    let Some(max_refresh_days) = sqlx::query_scalar::<_, Option<i32>>(
        "SELECT MAX(signature_refresh_days) FROM dnssec_policies",
    )
    .fetch_one(&mut *conn)
    .await?
    else {
        return Ok(0);
    };
    let bound = refresh_bound(cutoff, max_refresh_days);

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM dnssec_records r
        JOIN zones z ON z.id = r.zone_id
        JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
        WHERE r.expires_at IS NOT NULL
          AND r.expires_at < ?
          AND datetime(r.expires_at) < datetime(?, '+' || p.signature_refresh_days || ' days')
        "#,
    )
    .bind(bound)
    .bind(cutoff)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}

/// Count signatures that have already expired.
pub(crate) async fn count_expired_before(
    pool: &Pool<Sqlite>,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM dnssec_records
        WHERE expires_at IS NOT NULL
          AND expires_at <= ?
        "#,
    )
    .bind(cutoff)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}

/// List matching derived DNSSEC records with their zone metadata.
pub(crate) async fn list_by_filter_with_zone(
    pool: &Pool<Sqlite>,
    filter: DnssecRecordFilter,
) -> Result<Vec<DnssecRecordWithZone>, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let apex_owner = apex_owner_sql();
    let search = like_pattern(filter.search.as_deref());
    let grant_match = grant_record_match_sql("d", None, concat_pipes);
    let records = sqlx::query_as::<_, DnssecRecordWithZone>(AssertSqlSafe(format!(
        r#"
        SELECT d.name, d.record_type, d.ttl, d.rdata, d.zone_id, z.name AS zone_name
        FROM dnssec_records d
        INNER JOIN zones z ON z.id = d.zone_id
        WHERE (? IS NULL OR d.zone_id = (SELECT id FROM zones WHERE name = ?))
          AND (
                ? IS NULL
                OR LOWER(d.name) = LOWER(?)
                OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) = LOWER(?)
          )
          AND (? IS NULL OR d.record_type = ?)
          AND (? IS NULL OR d.ttl = ?)
          AND (? IS NULL OR d.ttl >= ?)
          AND (? IS NULL OR d.ttl <= ?)
          AND (
                ? IS NULL
                OR LOWER(z.name) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(d.name) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) LIKE LOWER(?) ESCAPE '\'
          )
          AND (
                ? IS NULL
                OR EXISTS (SELECT 1 FROM token_grants p
                           WHERE p.api_token_id = ? AND p.zone_id = d.zone_id
                             AND {grant_match})
          )
        -- every type at one name shares d.name, so without d.id a plan change
        -- between two pages could drop or repeat a row.
        ORDER BY d.name, d.id
        LIMIT ? OFFSET ?
        "#
    )))
    .bind(&filter.zone_name)
    .bind(&filter.zone_name)
    .bind(&filter.name)
    .bind(&filter.name)
    .bind(&filter.name)
    .bind(filter.record_type)
    .bind(filter.record_type)
    .bind(filter.ttl)
    .bind(filter.ttl)
    .bind(filter.min_ttl)
    .bind(filter.min_ttl)
    .bind(filter.max_ttl)
    .bind(filter.max_ttl)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(filter.scope_token_id)
    .bind(filter.scope_token_id)
    .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
    .bind(
        filter
            .offset
            .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
            .unwrap_or(0),
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(records)
}

/// Count derived DNSSEC records matching the filter.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    filter: DnssecRecordFilter,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let apex_owner = apex_owner_sql();
    let search = like_pattern(filter.search.as_deref());
    let grant_match = grant_record_match_sql("d", None, concat_pipes);
    let count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
        r#"
        SELECT COUNT(*)
        FROM dnssec_records d
        INNER JOIN zones z ON z.id = d.zone_id
        WHERE (? IS NULL OR d.zone_id = (SELECT id FROM zones WHERE name = ?))
          AND (
                ? IS NULL
                OR LOWER(d.name) = LOWER(?)
                OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) = LOWER(?)
          )
          AND (? IS NULL OR d.record_type = ?)
          AND (? IS NULL OR d.ttl = ?)
          AND (? IS NULL OR d.ttl >= ?)
          AND (? IS NULL OR d.ttl <= ?)
          AND (
                ? IS NULL
                OR LOWER(z.name) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(d.name) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) LIKE LOWER(?) ESCAPE '\'
          )
          AND (
                ? IS NULL
                OR EXISTS (SELECT 1 FROM token_grants p
                           WHERE p.api_token_id = ? AND p.zone_id = d.zone_id
                             AND {grant_match})
          )
        "#
    )))
    .bind(&filter.zone_name)
    .bind(&filter.zone_name)
    .bind(&filter.name)
    .bind(&filter.name)
    .bind(&filter.name)
    .bind(filter.record_type)
    .bind(filter.record_type)
    .bind(filter.ttl)
    .bind(filter.ttl)
    .bind(filter.min_ttl)
    .bind(filter.min_ttl)
    .bind(filter.max_ttl)
    .bind(filter.max_ttl)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(filter.scope_token_id)
    .bind(filter.scope_token_id)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}
