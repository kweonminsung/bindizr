use bindizr_core::model::role::RoleId;
use chrono::Utc;
use sqlx::{MySql, Pool, Transaction};

use crate::{error::DatabaseError, model::role::Role};

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

/// Find a role by ID.
pub(crate) async fn get(pool: &Pool<MySql>, id: RoleId) -> Result<Option<Role>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(role)
}

/// Find a role by name.
pub(crate) async fn get_by_name(
    pool: &Pool<MySql>,
    name: &str,
) -> Result<Option<Role>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(role)
}

/// List all roles.
pub(crate) async fn list_all(pool: &Pool<MySql>) -> Result<Vec<Role>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let roles = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(roles)
}

/// Delete a role by ID.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, MySql>,
    id: RoleId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM roles WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}
