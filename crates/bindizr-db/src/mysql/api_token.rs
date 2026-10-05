use bindizr_core::model::{api_token::TokenId, role::RoleId};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, MySql, Pool, Transaction};

use crate::{LockLevel, error::DatabaseError, model::api_token::ApiToken};

/// Insert an API token.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, MySql>,
    mut token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO api_tokens (name, token, description, role_id, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    "#,
    )
    .bind(&token.name)
    .bind(&token.token)
    .bind(&token.description)
    .bind(token.role_id)
    .bind(token.expires_at)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    token.id = TokenId::from(result.last_insert_id() as i32);
    token.created_at = now;

    Ok(token)
}

/// An API token by id in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, MySql>,
    id: TokenId,
    lock_level: LockLevel,
) -> Result<Option<ApiToken>, DatabaseError> {
    let row = sqlx::query_as::<_, ApiToken>(AssertSqlSafe(format!(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE id = ?{}",
        lock_level.clause(),
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row)
}

/// Find an API token by name.
pub(crate) async fn get_by_name(
    pool: &Pool<MySql>,
    name: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE name = ?"
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    ?;

    Ok(row)
}

/// Find an API token by its stored token hash.
pub(crate) async fn get_by_token(
    pool: &Pool<MySql>,
    token: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE token = ?"
    )
    .bind(token)
    .fetch_optional(&mut *conn)
    .await
    ?;

    Ok(row)
}

/// List all API tokens.
pub(crate) async fn list_all(pool: &Pool<MySql>) -> Result<Vec<ApiToken>, DatabaseError> {
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
    pool: &Pool<MySql>,
    id: TokenId,
    last_used_at: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(last_used_at)
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Delete an API token by ID.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, MySql>,
    id: TokenId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// List the API tokens authenticating into a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<MySql>,
    role_id: RoleId,
) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE role_id = ? ORDER BY created_at DESC, id DESC",
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows)
}
