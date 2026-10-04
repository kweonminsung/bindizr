use bindizr_core::model::{role::RoleId, role_grant::RoleGrantId, zone::ZoneId};
use chrono::Utc;
use sqlx::{Pool, Sqlite, Transaction};

use crate::{LockLevel, error::DatabaseError, model::role_grant::RoleGrant};

/// Insert a role grant.
pub(crate) async fn create(
    pool: &Pool<Sqlite>,
    mut grant: RoleGrant,
) -> Result<RoleGrant, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO role_grants (role_id, zone_id, actions, record_name_pattern, record_types, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(grant.role_id)
    .bind(grant.zone_scope.zone_id())
    .bind(&grant.actions)
    .bind(&grant.record_name_pattern)
    .bind(&grant.record_types)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    grant.id = RoleGrantId::from(result.last_insert_rowid() as i32);
    grant.created_at = now;
    Ok(grant)
}

/// Find a role grant by ID.
pub(crate) async fn get(
    pool: &Pool<Sqlite>,
    id: RoleGrantId,
) -> Result<Option<RoleGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grant = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(grant)
}

/// List every role's grants.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<RoleGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants ORDER BY id",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// List every grant of a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<Sqlite>,
    role_id: RoleId,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE role_id = ? ORDER BY id",
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// List every grant of a role in the current transaction; SQLite's writer
/// reservation stands in for a row lock.
pub(crate) async fn list_by_role_id_tx(
    tx: &mut Transaction<'_, Sqlite>,
    role_id: RoleId,
    _lock_level: LockLevel,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    let grants = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE role_id = ? ORDER BY id",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(grants)
}

/// List a role's grants that reach a zone, its all-zones grants included, in
/// the current transaction.
pub(crate) async fn list_by_role_id_covering_zone_tx(
    tx: &mut Transaction<'_, Sqlite>,
    role_id: RoleId,
    zone_id: ZoneId,
    _lock_level: LockLevel,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    let grants = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE role_id = ? AND (zone_id IS NULL OR zone_id = ?) ORDER BY id",
    )
    .bind(role_id)
    .bind(zone_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(grants)
}

/// Delete a role grant by ID.
pub(crate) async fn delete(pool: &Pool<Sqlite>, id: RoleGrantId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM role_grants WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
