use bindizr_core::{
    dns::{Serial, name::ZoneName},
    model::{dnssec_policy::PolicyId, zone::ZoneId},
};
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{
    LockLevel, error::DatabaseError, model::zone::Zone, sql::like_pattern, zone::ZoneFilter,
};

/// Insert a zone in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    mut zone: Zone,
) -> Result<Zone, DatabaseError> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO zones (name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, parent_ns_addrs, enabled, description, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id
        "#,
    )
    .bind(&zone.name)
    .bind(&zone.mname)
    .bind(&zone.rname)
    .bind(zone.default_ttl)
    .bind(zone.serial)
    .bind(zone.refresh)
    .bind(zone.retry)
    .bind(zone.expire)
    .bind(zone.minimum_ttl)
    .bind(&zone.parent_ns_addrs)
    .bind(zone.enabled)
    .bind(&zone.description)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;

    zone.id = ZoneId::from(result.get::<i32, _>(0));
    zone.created_at = now;
    Ok(zone)
}

/// Find a zone by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: ZoneId,
    lock_level: LockLevel,
) -> Result<Option<Zone>, DatabaseError> {
    let zone = sqlx::query_as::<_, Zone>(AssertSqlSafe(format!("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones WHERE id = $1{}",lock_level.clause())))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;

    Ok(zone)
}

/// Find a zone by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Postgres>,
    name: &ZoneName,
) -> Result<Option<Zone>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones WHERE name = $1")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

    Ok(zone)
}

/// Find a zone by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Postgres>,
    name: &ZoneName,
    lock_level: LockLevel,
) -> Result<Option<Zone>, DatabaseError> {
    let zone = sqlx::query_as::<_, Zone>(AssertSqlSafe(
        format!("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones WHERE name = $1{}",
        lock_level.clause(),
    )))
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(zone)
}

/// List all zones.
pub(crate) async fn list_all(pool: &Pool<Postgres>) -> Result<Vec<Zone>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let zones = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones ORDER BY name")
        .fetch_all(&mut *conn)
        .await?;

    Ok(zones)
}

/// List all zones in the current transaction.
pub(crate) async fn list_all_tx(
    tx: &mut Transaction<'_, Postgres>,
    lock_level: LockLevel,
) -> Result<Vec<Zone>, DatabaseError> {
    let zones = sqlx::query_as::<_, Zone>(AssertSqlSafe(format!("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones ORDER BY name{}",lock_level.clause())))
        .fetch_all(&mut **tx)
        .await?;

    Ok(zones)
}

/// List zones matching the filter.
pub(crate) async fn list_by_filter(
    pool: &Pool<Postgres>,
    filter: ZoneFilter,
) -> Result<Vec<Zone>, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let search = like_pattern(filter.search.as_deref());

    let order_by = filter.sort.order_by_sql(filter.order);
    let zones = sqlx::query_as::<_, Zone>(AssertSqlSafe(format!(
        r#"
        SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at
        FROM zones
        WHERE ($1::TEXT IS NULL OR LOWER(name) = LOWER($2))
          AND ($3::INT4 IS NULL OR id = $4)
          AND ($5::TEXT IS NULL OR LOWER(mname) = LOWER($6))
          AND ($7::TEXT IS NULL OR LOWER(rname) = LOWER($8))
          AND ($9::INT4 IS NULL OR default_ttl = $10)
          AND ($11::INT4 IS NULL OR default_ttl >= $12)
          AND ($13::INT4 IS NULL OR default_ttl <= $14)
          AND ($15::INT4 IS NULL OR serial = $16)
          AND ($17::INT4 IS NULL OR serial >= $18)
          AND ($19::INT4 IS NULL OR serial <= $20)
          AND ($21::TIMESTAMPTZ IS NULL OR created_at >= $22)
          AND ($23::TIMESTAMPTZ IS NULL OR created_at <= $24)
          AND ($25::BOOL IS NULL OR (dnssec_policy_id IS NOT NULL) = $26)
          AND ($27::BOOL IS NULL OR enabled = $28)
          AND (
                $29::TEXT IS NULL
                OR LOWER(name) LIKE LOWER($30) ESCAPE '\'
                OR LOWER(mname) LIKE LOWER($31) ESCAPE '\'
                OR LOWER(rname) LIKE LOWER($32) ESCAPE '\'
          )
          AND (
                $35::INT4 IS NULL
                OR EXISTS (SELECT 1 FROM token_grants p
                           WHERE p.api_token_id = $35 AND p.zone_id = zones.id)
          )
        {order_by}
        LIMIT $33 OFFSET $34
        "#
    )))
    .bind(&filter.name)
    .bind(&filter.name)
    .bind(filter.id)
    .bind(filter.id)
    .bind(&filter.mname)
    .bind(&filter.mname)
    .bind(&filter.rname)
    .bind(&filter.rname)
    .bind(filter.default_ttl)
    .bind(filter.default_ttl)
    .bind(filter.min_default_ttl)
    .bind(filter.min_default_ttl)
    .bind(filter.max_default_ttl)
    .bind(filter.max_default_ttl)
    .bind(filter.serial)
    .bind(filter.serial)
    .bind(filter.min_serial)
    .bind(filter.min_serial)
    .bind(filter.max_serial)
    .bind(filter.max_serial)
    .bind(filter.created_after)
    .bind(filter.created_after)
    .bind(filter.created_before)
    .bind(filter.created_before)
    .bind(filter.signed)
    .bind(filter.signed)
    .bind(filter.enabled)
    .bind(filter.enabled)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
    .bind(
        filter
            .offset
            .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
            .unwrap_or(0),
    )
    .bind(filter.scope_token_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(zones)
}

/// Probe the zones table to check database connectivity.
pub(crate) async fn ping(pool: &Pool<Postgres>) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT 1 FROM zones LIMIT 1")
        .fetch_optional(&mut *conn)
        .await?;
    Ok(())
}

/// Count zones matching the filter.
pub(crate) async fn count_by_filter(
    pool: &Pool<Postgres>,
    filter: ZoneFilter,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let search = like_pattern(filter.search.as_deref());

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM zones
        WHERE ($1::TEXT IS NULL OR LOWER(name) = LOWER($2))
          AND ($3::INT4 IS NULL OR id = $4)
          AND ($5::TEXT IS NULL OR LOWER(mname) = LOWER($6))
          AND ($7::TEXT IS NULL OR LOWER(rname) = LOWER($8))
          AND ($9::INT4 IS NULL OR default_ttl = $10)
          AND ($11::INT4 IS NULL OR default_ttl >= $12)
          AND ($13::INT4 IS NULL OR default_ttl <= $14)
          AND ($15::INT4 IS NULL OR serial = $16)
          AND ($17::INT4 IS NULL OR serial >= $18)
          AND ($19::INT4 IS NULL OR serial <= $20)
          AND ($21::TIMESTAMPTZ IS NULL OR created_at >= $22)
          AND ($23::TIMESTAMPTZ IS NULL OR created_at <= $24)
          AND ($25::BOOL IS NULL OR (dnssec_policy_id IS NOT NULL) = $26)
          AND ($27::BOOL IS NULL OR enabled = $28)
          AND (
                $29::TEXT IS NULL
                OR LOWER(name) LIKE LOWER($30) ESCAPE '\'
                OR LOWER(mname) LIKE LOWER($31) ESCAPE '\'
                OR LOWER(rname) LIKE LOWER($32) ESCAPE '\'
          )
          AND (
                $33::INT4 IS NULL
                OR EXISTS (SELECT 1 FROM token_grants p
                           WHERE p.api_token_id = $33 AND p.zone_id = zones.id)
          )
        "#,
    )
    .bind(&filter.name)
    .bind(&filter.name)
    .bind(filter.id)
    .bind(filter.id)
    .bind(&filter.mname)
    .bind(&filter.mname)
    .bind(&filter.rname)
    .bind(&filter.rname)
    .bind(filter.default_ttl)
    .bind(filter.default_ttl)
    .bind(filter.min_default_ttl)
    .bind(filter.min_default_ttl)
    .bind(filter.max_default_ttl)
    .bind(filter.max_default_ttl)
    .bind(filter.serial)
    .bind(filter.serial)
    .bind(filter.min_serial)
    .bind(filter.min_serial)
    .bind(filter.max_serial)
    .bind(filter.max_serial)
    .bind(filter.created_after)
    .bind(filter.created_after)
    .bind(filter.created_before)
    .bind(filter.created_before)
    .bind(filter.signed)
    .bind(filter.signed)
    .bind(filter.enabled)
    .bind(filter.enabled)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(&search)
    .bind(filter.scope_token_id)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}

/// Update a zone in the current transaction.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone: Zone,
) -> Result<Zone, DatabaseError> {
    sqlx::query(
        r#"
        UPDATE zones 
        SET name = $1, mname = $2, rname = $3,
            default_ttl = $4, serial = $5, refresh = $6, retry = $7, expire = $8, minimum_ttl = $9,
            enabled = $10, description = $11
        WHERE id = $12
        "#,
    )
    .bind(&zone.name)
    .bind(&zone.mname)
    .bind(&zone.rname)
    .bind(zone.default_ttl)
    .bind(zone.serial)
    .bind(zone.refresh)
    .bind(zone.retry)
    .bind(zone.expire)
    .bind(zone.minimum_ttl)
    .bind(zone.enabled)
    .bind(&zone.description)
    .bind(zone.id)
    .execute(&mut **tx)
    .await?;

    Ok(zone)
}

/// Set or clear a zone's DNSSEC policy assignment in the current transaction.
pub(crate) async fn update_dnssec_policy_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    dnssec_policy_id: Option<PolicyId>,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE zones SET dnssec_policy_id = $1 WHERE id = $2")
        .bind(dnssec_policy_id)
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Set or clear a zone's configured parent name servers in the current transaction.
pub(crate) async fn update_parent_ns_addrs_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    parent_ns_addrs: Option<&str>,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE zones SET parent_ns_addrs = $1 WHERE id = $2")
        .bind(parent_ns_addrs)
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Count zones using a DNSSEC policy.
pub(crate) async fn count_by_dnssec_policy_id(
    pool: &Pool<Postgres>,
    dnssec_policy_id: PolicyId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM zones WHERE dnssec_policy_id = $1")
            .bind(dnssec_policy_id)
            .fetch_one(&mut *conn)
            .await?;

    Ok(count as u64)
}

/// Update only a zone's serial in the current transaction.
pub(crate) async fn update_serial_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    serial: Serial,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE zones SET serial = $1 WHERE id = $2")
        .bind(serial)
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Delete a zone by ID in the current transaction.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: ZoneId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM zones WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
