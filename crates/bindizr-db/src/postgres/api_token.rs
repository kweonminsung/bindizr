use bindizr_core::model::{api_token::TokenId, role::RoleId};
use chrono::Utc;
use sqlx::{Pool, Postgres, Row};

use crate::{error::DatabaseError, model::api_token::ApiToken};

/// Insert an API token.
pub(crate) async fn create(
    pool: &Pool<Postgres>,
    mut token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO api_tokens (name, token, description, role_id, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
    "#,
    )
    .bind(&token.name)
    .bind(&token.token)
    .bind(&token.description)
    .bind(token.role_id)
    .bind(token.expires_at)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;

    token.id = TokenId::from(result.get::<i32, _>(0));
    token.created_at = now;

    Ok(token)
}

/// Find an API token by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Postgres>,
    name: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE name = $1"
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    ?;

    Ok(row)
}

/// Find an API token by its stored token hash.
pub(crate) async fn get_by_token(
    pool: &Pool<Postgres>,
    token: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE token = $1"
    )
    .bind(token)
    .fetch_optional(&mut *conn)
    .await
    ?;

    Ok(row)
}

/// List all API tokens.
pub(crate) async fn list_all(pool: &Pool<Postgres>) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC, id DESC"
    )
    .fetch_all(&mut *conn)
    .await
    ?;

    Ok(rows)
}

/// Update an API token.
pub(crate) async fn update(
    pool: &Pool<Postgres>,
    token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query(
        r#"
        UPDATE api_tokens 
        SET description = $1, expires_at = $2, last_used_at = $3
        WHERE id = $4
    "#,
    )
    .bind(&token.description)
    .bind(token.expires_at)
    .bind(token.last_used_at)
    .bind(token.id)
    .execute(&mut *conn)
    .await?;

    Ok(token)
}

/// Delete an API token by ID.
pub(crate) async fn delete(pool: &Pool<Postgres>, id: TokenId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM api_tokens WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Count the API tokens authenticating into a role: the in-use check before a role delete.
pub(crate) async fn count_by_role_id(
    pool: &Pool<Postgres>,
    role_id: RoleId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_tokens WHERE role_id = $1")
        .bind(role_id)
        .fetch_one(&mut *conn)
        .await?;

    Ok(count as u64)
}
