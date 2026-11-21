use bindizr_core::model::role::{Role, RoleId, RoleWithCounts};
use chrono::Utc;
use sqlx::{MySql, Pool, Transaction};

use crate::error::DatabaseError;

/// Insert a role.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, MySql>,
    mut role: Role,
) -> Result<Role, DatabaseError> {
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO roles (name, description, created_at)
        VALUES (?, ?, ?)
        "#,
    )
    .bind(&role.name)
    .bind(&role.description)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    role.id = RoleId::from(result.last_insert_id() as i32);
    role.created_at = now;

    Ok(role)
}

/// Get a role by ID.
pub(crate) async fn get(pool: &Pool<MySql>, id: RoleId) -> Result<Option<Role>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(role)
}

/// Get a role by name.
pub(crate) async fn get_by_name(
    pool: &Pool<MySql>,
    name: &str,
) -> Result<Option<Role>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(role)
}

/// Delete a role by ID; its grants go with it. Reports `false` when no row had
/// the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, MySql>,
    id: RoleId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM roles WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List roles with their grant and credential counts in name order, applying the supplied window.
pub(crate) async fn list_all_with_counts(
    pool: &Pool<MySql>,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<RoleWithCounts>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let roles = sqlx::query_as::<_, RoleWithCounts>(
        r#"
        SELECT r.id, r.name, r.description, r.created_at,
               (SELECT COUNT(*) FROM role_grants g WHERE g.role_id = r.id) AS grant_count,
               (SELECT COUNT(*) FROM api_tokens t WHERE t.role_id = r.id) AS token_count,
               (SELECT COUNT(*) FROM tsig_keys k WHERE k.role_id = r.id) AS tsig_key_count
        FROM roles r
        ORDER BY r.name
        LIMIT ?
        OFFSET ?
        "#,
    )
    .bind(limit.map_or(i64::MAX, i64::from))
    .bind(offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;

    Ok(roles)
}

/// Get a role by name with its grant and credential counts.
pub(crate) async fn get_by_name_with_counts(
    pool: &Pool<MySql>,
    name: &str,
) -> Result<Option<RoleWithCounts>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let role = sqlx::query_as::<_, RoleWithCounts>(
        r#"
        SELECT r.id, r.name, r.description, r.created_at,
               (SELECT COUNT(*) FROM role_grants g WHERE g.role_id = r.id) AS grant_count,
               (SELECT COUNT(*) FROM api_tokens t WHERE t.role_id = r.id) AS token_count,
               (SELECT COUNT(*) FROM tsig_keys k WHERE k.role_id = r.id) AS tsig_key_count
        FROM roles r
        WHERE r.name = ?
        "#,
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(role)
}

/// Count all roles.
pub(crate) async fn count_all(pool: &Pool<MySql>) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM roles"#)
        .fetch_one(&mut *connection)
        .await?;

    Ok(count as u64)
}
