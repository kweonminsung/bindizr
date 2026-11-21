use bindizr_core::model::role::RoleId;
use bindizr_core::model::role_grant::{RoleGrant, RoleGrantId, RoleGrantWithZone};
use chrono::Utc;
use sqlx::{Pool, Postgres, Row, Transaction};

use crate::error::DatabaseError;

/// Insert a role grant.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    mut grant: RoleGrant,
) -> Result<RoleGrant, DatabaseError> {
    let now = Utc::now();

    let row = sqlx::query(
        r#"
        INSERT INTO role_grants (role_id, zone_id, actions, record_name_pattern, record_types, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(grant.role_id)
    .bind(grant.zone_scope.zone_id())
    .bind(&grant.actions)
    .bind(&grant.record_name_pattern)
    .bind(&grant.record_types)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;

    grant.id = RoleGrantId::from(row.get::<i32, _>(0));
    grant.created_at = now;

    Ok(grant)
}

/// Get a role grant by ID.
pub(crate) async fn get(
    pool: &Pool<Postgres>,
    grant_id: RoleGrantId,
) -> Result<Option<RoleGrant>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let grant = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE id = $1",
    )
    .bind(grant_id)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(grant)
}

/// List every grant of a role, which bounds what a credential of it may see.
pub(crate) async fn list_by_role_id(
    pool: &Pool<Postgres>,
    role_id: RoleId,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let grants = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE role_id = $1 ORDER BY id",
    )
    .bind(role_id)
    .fetch_all(&mut *connection)
    .await?;

    Ok(grants)
}

/// List every grant of a role in the current transaction, share-locked,
/// for a mutation to authorize against.
pub(crate) async fn list_by_role_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    role_id: RoleId,
) -> Result<Vec<RoleGrant>, DatabaseError> {
    let grants = sqlx::query_as::<_, RoleGrant>(
        "SELECT id, role_id, zone_id, actions, record_name_pattern, record_types, created_at FROM role_grants WHERE role_id = $1 ORDER BY id FOR SHARE",
    )
    .bind(role_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(grants)
}

/// Delete a role grant by ID.
/// Reports `false` when no row had the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Postgres>,
    grant_id: RoleGrantId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM role_grants WHERE id = $1")
        .bind(grant_id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List a role's grants with zone names in id order, applying the supplied window.
pub(crate) async fn list_by_role_id_with_zone(
    pool: &Pool<Postgres>,
    role_id: RoleId,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<RoleGrantWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let grants = sqlx::query_as::<_, RoleGrantWithZone>(
        r#"
        SELECT g.id, g.role_id, g.zone_id, g.actions, g.record_name_pattern, g.record_types, g.created_at, z.name AS zone_name
        FROM role_grants g
        LEFT JOIN zones z ON z.id = g.zone_id
        WHERE g.role_id = $1
        ORDER BY g.id
        LIMIT $2
        OFFSET $3
        "#,
    )
    .bind(role_id)
    .bind(limit.map_or(i64::MAX, i64::from))
    .bind(offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;

    Ok(grants)
}

/// Count the grants of one role.
pub(crate) async fn count_by_role_id(
    pool: &Pool<Postgres>,
    role_id: RoleId,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM role_grants WHERE role_id = $1"#)
            .bind(role_id)
            .fetch_one(&mut *connection)
            .await?;

    Ok(count as u64)
}
