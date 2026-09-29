use bindizr_core::model::api_token::TokenId;
use chrono::Utc;
use sqlx::{Pool, Sqlite};

use crate::{error::DatabaseError, model::api_token::ApiToken};

/// Insert an API token.
pub(crate) async fn create(
    pool: &Pool<Sqlite>,
    mut token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO api_tokens (name, token, description, is_global, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&token.name)
    .bind(&token.token)
    .bind(&token.description)
    .bind(token.is_global)
    .bind(token.expires_at)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    token.id = TokenId::from(result.last_insert_rowid() as i32);
    token.created_at = now;
    Ok(token)
}

/// Find an API token by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, is_global, expires_at, created_at, last_used_at FROM api_tokens WHERE name = ?"
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    ?;

    Ok(row)
}

/// Find an API token by its stored token hash.
pub(crate) async fn get_by_token(
    pool: &Pool<Sqlite>,
    token: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, is_global, expires_at, created_at, last_used_at FROM api_tokens WHERE token = ?"
    )
    .bind(token)
    .fetch_optional(&mut *conn)
    .await
    ?;

    Ok(row)
}

/// List all API tokens.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, is_global, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC, id DESC"
    )
    .fetch_all(&mut *conn)
    .await
    ?;

    Ok(rows)
}

/// Update an API token.
pub(crate) async fn update(
    pool: &Pool<Sqlite>,
    token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query(
        r#"
        UPDATE api_tokens 
        SET description = ?, expires_at = ?, last_used_at = ?
        WHERE id = ?
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
pub(crate) async fn delete(pool: &Pool<Sqlite>, id: TokenId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
