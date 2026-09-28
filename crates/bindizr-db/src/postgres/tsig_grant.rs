use bindizr_core::model::{tsig_grant::TsigGrantId, tsig_key::TsigKeyId, zone::ZoneId};
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{LockLevel, error::DatabaseError, model::tsig_grant::TsigGrant};

/// Insert a TSIG grant.
pub(crate) async fn create(
    pool: &Pool<Postgres>,
    mut grant: TsigGrant,
) -> Result<TsigGrant, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO tsig_grants (zone_id, tsig_key_id, record_name_pattern, record_types, can_write, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(grant.zone_id)
    .bind(grant.tsig_key_id)
    .bind(&grant.record_name_pattern)
    .bind(&grant.record_types)
    .bind(grant.can_write)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;

    grant.id = TsigGrantId::from(result.get::<i32, _>(0));
    grant.created_at = now;

    Ok(grant)
}

/// Find a TSIG grant by ID.
pub(crate) async fn get(
    pool: &Pool<Postgres>,
    id: TsigGrantId,
) -> Result<Option<TsigGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grant = sqlx::query_as::<_, TsigGrant>(
        "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, can_write, created_at FROM tsig_grants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(grant)
}

/// List TSIG grants for a zone.
pub(crate) async fn list_by_zone_id(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
) -> Result<Vec<TsigGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, TsigGrant>(
        "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, can_write, created_at FROM tsig_grants WHERE zone_id = $1 ORDER BY id",
    )
    .bind(zone_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// List TSIG grants for a TSIG key in a zone in the current transaction.
pub(crate) async fn list_by_zone_id_and_key_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    tsig_key_id: TsigKeyId,
    lock_level: LockLevel,
) -> Result<Vec<TsigGrant>, DatabaseError> {
    let grants = sqlx::query_as::<_, TsigGrant>(AssertSqlSafe(
        format!("SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, can_write, created_at FROM tsig_grants WHERE zone_id = $1 AND tsig_key_id = $2 ORDER BY id{}",
        lock_level.clause(),
    )))
    .bind(zone_id)
    .bind(tsig_key_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(grants)
}

/// List TSIG grants for a TSIG key.
pub(crate) async fn list_by_key_id(
    pool: &Pool<Postgres>,
    tsig_key_id: TsigKeyId,
) -> Result<Vec<TsigGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, TsigGrant>(
        "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, can_write, created_at FROM tsig_grants WHERE tsig_key_id = $1 ORDER BY id",
    )
    .bind(tsig_key_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// Count TSIG grants for a TSIG key.
pub(crate) async fn count_by_key_id(
    pool: &Pool<Postgres>,
    tsig_key_id: TsigKeyId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tsig_grants WHERE tsig_key_id = $1")
            .bind(tsig_key_id)
            .fetch_one(&mut *conn)
            .await?;

    Ok(count as u64)
}

/// Delete a TSIG grant by ID.
pub(crate) async fn delete(pool: &Pool<Postgres>, id: TsigGrantId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM tsig_grants WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Delete every grant a TSIG key holds in one zone, returning how many rows went.
pub(crate) async fn delete_by_key_id_and_zone_id(
    pool: &Pool<Postgres>,
    tsig_key_id: TsigKeyId,
    zone_id: ZoneId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let result = sqlx::query("DELETE FROM tsig_grants WHERE tsig_key_id = $1 AND zone_id = $2")
        .bind(tsig_key_id)
        .bind(zone_id)
        .execute(&mut *conn)
        .await?;

    Ok(result.rows_affected())
}
