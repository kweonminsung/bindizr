use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Sqlite, Transaction};

use crate::{
    LockLevel, error::DatabaseError, model::zone::Zone, sql::like_pattern, zone::ZoneFilter,
};

/// Insert a zone in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    mut zone: Zone,
) -> Result<Zone, DatabaseError> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO zones (name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, parent_ns_addrs, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(zone.name.as_str())
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
    .execute(&mut **tx)
    .await?;

    zone.id = result.last_insert_rowid() as i32;
    zone.created_at = now;
    Ok(zone)
}

/// Find a zone by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: i32,
    _lock_level: LockLevel,
) -> Result<Option<Zone>, DatabaseError> {
    let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;

    Ok(zone)
}

/// Find a zone by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<Zone>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones WHERE name = ?")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

    Ok(zone)
}

/// Find a zone by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    _lock_level: LockLevel,
) -> Result<Option<Zone>, DatabaseError> {
    let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones WHERE name = ?")
        .bind(name)
        .fetch_optional(&mut **tx)
        .await?;

    Ok(zone)
}

/// List all zones.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<Zone>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let zones = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones ORDER BY name")
        .fetch_all(&mut *conn)
        .await?;

    Ok(zones)
}

/// List all zones in the current transaction.
pub(crate) async fn list_all_tx(
    tx: &mut Transaction<'_, Sqlite>,
    _lock_level: LockLevel,
) -> Result<Vec<Zone>, DatabaseError> {
    let zones = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at FROM zones ORDER BY name")
        .fetch_all(&mut **tx)
        .await?;

    Ok(zones)
}

/// List zones matching the filter.
pub(crate) async fn list_by_filter(
    pool: &Pool<Sqlite>,
    filter: ZoneFilter,
) -> Result<Vec<Zone>, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let search = like_pattern(filter.search.as_deref());

    let order_by = filter.sort.order_by_sql(filter.order);
    let zones = sqlx::query_as::<_, Zone>(AssertSqlSafe(format!(
        r#"
        SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, parent_ns_addrs, enabled, description, created_at
        FROM zones
        WHERE (? IS NULL OR LOWER(name) = LOWER(?))
          AND (? IS NULL OR id = ?)
          AND (? IS NULL OR LOWER(mname) = LOWER(?))
          AND (? IS NULL OR LOWER(rname) = LOWER(?))
          AND (? IS NULL OR default_ttl = ?)
          AND (? IS NULL OR default_ttl >= ?)
          AND (? IS NULL OR default_ttl <= ?)
          AND (? IS NULL OR serial = ?)
          AND (? IS NULL OR serial >= ?)
          AND (? IS NULL OR serial <= ?)
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at <= ?)
          AND (? IS NULL OR (dnssec_policy_id IS NOT NULL) = ?)
          AND (? IS NULL OR enabled = ?)
          AND (
                ? IS NULL
                OR LOWER(name) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(mname) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(rname) LIKE LOWER(?) ESCAPE '\'
          )
          AND (
                ? IS NULL
                OR EXISTS (SELECT 1 FROM token_grants p
                           WHERE p.api_token_id = ? AND p.zone_id = zones.id)
          )
        {order_by}
        LIMIT ? OFFSET ?
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

    Ok(zones)
}

/// Probe the zones table to check database connectivity.
pub(crate) async fn ping(pool: &Pool<Sqlite>) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT 1 FROM zones LIMIT 1")
        .fetch_optional(&mut *conn)
        .await?;
    Ok(())
}

/// Count zones matching the filter.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    filter: ZoneFilter,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;
    let search = like_pattern(filter.search.as_deref());

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM zones
        WHERE (? IS NULL OR LOWER(name) = LOWER(?))
          AND (? IS NULL OR id = ?)
          AND (? IS NULL OR LOWER(mname) = LOWER(?))
          AND (? IS NULL OR LOWER(rname) = LOWER(?))
          AND (? IS NULL OR default_ttl = ?)
          AND (? IS NULL OR default_ttl >= ?)
          AND (? IS NULL OR default_ttl <= ?)
          AND (? IS NULL OR serial = ?)
          AND (? IS NULL OR serial >= ?)
          AND (? IS NULL OR serial <= ?)
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at <= ?)
          AND (? IS NULL OR (dnssec_policy_id IS NOT NULL) = ?)
          AND (? IS NULL OR enabled = ?)
          AND (
                ? IS NULL
                OR LOWER(name) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(mname) LIKE LOWER(?) ESCAPE '\'
                OR LOWER(rname) LIKE LOWER(?) ESCAPE '\'
          )
          AND (
                ? IS NULL
                OR EXISTS (SELECT 1 FROM token_grants p
                           WHERE p.api_token_id = ? AND p.zone_id = zones.id)
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
    .bind(filter.scope_token_id)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}

/// Update a zone in the current transaction.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone: Zone,
) -> Result<Zone, DatabaseError> {
    sqlx::query(
        r#"
        UPDATE zones 
        SET name = ?, mname = ?, rname = ?,
            default_ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ?,
            enabled = ?, description = ?
        WHERE id = ?
        "#,
    )
    .bind(zone.name.as_str())
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
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
    dnssec_policy_id: Option<i32>,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE zones SET dnssec_policy_id = ? WHERE id = ?")
        .bind(dnssec_policy_id)
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Set or clear a zone's configured parent name servers in the current transaction.
pub(crate) async fn update_parent_ns_addrs_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
    parent_ns_addrs: Option<&str>,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE zones SET parent_ns_addrs = ? WHERE id = ?")
        .bind(parent_ns_addrs)
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Count zones using a DNSSEC policy.
pub(crate) async fn count_by_dnssec_policy_id(
    pool: &Pool<Sqlite>,
    dnssec_policy_id: i32,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM zones WHERE dnssec_policy_id = ?")
            .bind(dnssec_policy_id)
            .fetch_one(&mut *conn)
            .await?;

    Ok(count as u64)
}

/// Update only a zone's serial in the current transaction.
pub(crate) async fn update_serial_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
    serial: i32,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE zones SET serial = ? WHERE id = ?")
        .bind(serial)
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Delete a zone by ID in the current transaction.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: i32,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM zones WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
