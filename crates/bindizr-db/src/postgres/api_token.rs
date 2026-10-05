use bindizr_core::model::{api_token::TokenId, role::RoleId};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{LockLevel, error::DatabaseError, model::api_token::ApiToken};

/// Insert an API token.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    mut token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
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
    .fetch_one(&mut **tx)
    .await?;

    token.id = TokenId::from(result.get::<i32, _>(0));
    token.created_at = now;

    Ok(token)
}

/// An API token by id in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: TokenId,
    lock_level: LockLevel,
) -> Result<Option<ApiToken>, DatabaseError> {
    let row = sqlx::query_as::<_, ApiToken>(AssertSqlSafe(format!(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE id = $1{}",
        lock_level.clause(),
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row)
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

/// Stamp when the token was last used.
pub(crate) async fn update_last_used_at(
    pool: &Pool<Postgres>,
    id: TokenId,
    last_used_at: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("UPDATE api_tokens SET last_used_at = $1 WHERE id = $2")
        .bind(last_used_at)
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Delete an API token by ID.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: TokenId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM api_tokens WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// List the API tokens authenticating into a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<Postgres>,
    role_id: RoleId,
) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE role_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows)
}
