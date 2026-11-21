use bindizr_core::model::api_token::{ApiToken, ApiTokenMetadata, TokenId};
use bindizr_core::model::role::RoleId;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres, Row, Transaction};

use crate::api_token::ApiTokenFilter;
use crate::error::DatabaseError;

/// Insert an API token.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    mut token: ApiToken,
) -> Result<ApiToken, DatabaseError> {
    let now = Utc::now();

    let row = sqlx::query(
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

    token.id = TokenId::from(row.get::<i32, _>(0));
    token.created_at = now;

    Ok(token)
}

/// Get an API token by ID in the current transaction, share-locked.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Postgres>,
    token_id: TokenId,
) -> Result<Option<ApiToken>, DatabaseError> {
    let token = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE id = $1 FOR SHARE",
    )
    .bind(token_id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(token)
}

/// Get an API token by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Postgres>,
    name: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let token = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(token)
}

/// Get an API token by its stored token hash.
pub(crate) async fn get_by_token(
    pool: &Pool<Postgres>,
    token: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let token = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(token)
}

/// Count all API tokens.
pub(crate) async fn count_all(pool: &Pool<Postgres>) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_tokens")
        .fetch_one(&mut *connection)
        .await?;

    Ok(count as u64)
}

/// Stamp when the token was last used, returning whether it was stamped; a
/// row a transaction holds is skipped, not waited for.
pub(crate) async fn update_last_used_at(
    pool: &Pool<Postgres>,
    token_id: TokenId,
    last_used_at: DateTime<Utc>,
) -> Result<bool, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let result = sqlx::query(
        r#"
        UPDATE api_tokens SET last_used_at = $1
        WHERE id = (SELECT id FROM api_tokens WHERE id = $2 FOR UPDATE SKIP LOCKED)
        "#,
    )
    .bind(last_used_at)
    .bind(token_id)
    .execute(&mut *connection)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete an API token by ID.
/// Reports `false` when no row had the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Postgres>,
    token_id: TokenId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM api_tokens WHERE id = $1")
        .bind(token_id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List the API tokens authenticating into a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<Postgres>,
    role_id: RoleId,
) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tokens = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE role_id = $1 ORDER BY created_at DESC, id DESC",
    )
    .bind(role_id)
    .fetch_all(&mut *connection)
    .await?;

    Ok(tokens)
}

/// List credential metadata with its role name, filtered and paged in SQL.
pub(crate) async fn list_by_filter_with_role(
    pool: &Pool<Postgres>,
    filter: &ApiTokenFilter,
) -> Result<Vec<ApiTokenMetadata>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tokens = sqlx::query_as::<_, ApiTokenMetadata>(
        r#"
        SELECT t.id, t.name, t.description, r.name AS role_name, t.created_at, t.expires_at, t.last_used_at
        FROM api_tokens t
        INNER JOIN roles r ON r.id = t.role_id
        WHERE ($1::INT4 IS NULL OR t.role_id = $2)
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT $3
        OFFSET $4
        "#,
    )
    .bind(filter.role_id)
    .bind(filter.role_id)
    .bind(filter.limit.map_or(i64::MAX, i64::from))
    .bind(filter.offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;

    Ok(tokens)
}

/// Count credentials matching the role filter, ignoring its page window.
pub(crate) async fn count_by_filter(
    pool: &Pool<Postgres>,
    filter: &ApiTokenFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM api_tokens t
        INNER JOIN roles r ON r.id = t.role_id
        WHERE ($1::INT4 IS NULL OR t.role_id = $2)
        "#,
    )
    .bind(filter.role_id)
    .bind(filter.role_id)
    .fetch_one(&mut *connection)
    .await?;

    Ok(count as u64)
}
