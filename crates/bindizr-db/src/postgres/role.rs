use bindizr_core::model::role::RoleId;
use chrono::Utc;
use sqlx::{Pool, Postgres, Row, Transaction};

use crate::{error::DatabaseError, model::role::Role};

/// Insert a role.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    mut role: Role,
) -> Result<Role, DatabaseError> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO roles (name, description, created_at)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
    )
    .bind(&role.name)
    .bind(&role.description)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;

    role.id = RoleId::from(result.get::<i32, _>(0));
    role.created_at = now;
    Ok(role)
}

/// Find a role by ID.
pub(crate) async fn get(pool: &Pool<Postgres>, id: RoleId) -> Result<Option<Role>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(role)
}

/// Find a role by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Postgres>,
    name: &str,
) -> Result<Option<Role>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM roles WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(role)
}

/// List all roles.
pub(crate) async fn list_all(pool: &Pool<Postgres>) -> Result<Vec<Role>, DatabaseError> {
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
    tx: &mut Transaction<'_, Postgres>,
    id: RoleId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}
