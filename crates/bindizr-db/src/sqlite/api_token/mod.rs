use bindizr_core::model::api_token::{ApiToken, ApiTokenMetadata, TokenId};
use bindizr_core::model::role::RoleId;
use chrono::{DateTime, Utc};
use sqlx::pool::PoolConnection;
use sqlx::{Pool, Sqlite, Transaction};

use crate::api_token::ApiTokenFilter;
use crate::error::DatabaseError;
use crate::sqlite;

/// Insert an API token.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
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

    token.id = TokenId::from(sqlite::last_insert_id(&result)?);
    token.created_at = now;

    Ok(token)
}

/// Get an API token by ID in the current transaction, share-locked.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: TokenId,
) -> Result<Option<ApiToken>, DatabaseError> {
    let token = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(token)
}

/// Get an API token by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let token = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(token)
}

/// Get an API token by its stored token hash.
pub(crate) async fn get_by_token(
    pool: &Pool<Sqlite>,
    token: &str,
) -> Result<Option<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let token = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE token = ?",
    )
    .bind(token)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(token)
}

/// Count all API tokens.
pub(crate) async fn count_all(pool: &Pool<Sqlite>) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_tokens")
        .fetch_one(&mut *connection)
        .await?;

    Ok(count as u64)
}

/// Stamp when the token was last used, returning whether it was stamped. A
/// mutation holds the database writer for its whole transaction, so the stamp
/// gives up at once rather than wait for it: nothing may block on a stamp.
pub(crate) async fn update_last_used_at(
    pool: &Pool<Sqlite>,
    id: TokenId,
    last_used_at: DateTime<Utc>,
) -> Result<bool, DatabaseError> {
    let mut stamp = StampConnection {
        connection: pool.acquire().await?,
        restored: false,
    };

    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&mut *stamp.connection)
        .await?;

    let stamped = match sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(last_used_at)
        .bind(id)
        .execute(&mut *stamp.connection)
        .await
    {
        Ok(result) => result.rows_affected() > 0,
        Err(sqlx::Error::Database(error)) if sqlite::is_busy(error.as_ref()) => false,
        Err(error) => return Err(error.into()),
    };

    sqlx::query(sqlite::BUSY_TIMEOUT_PRAGMA)
        .execute(&mut *stamp.connection)
        .await?;
    stamp.restored = true;

    Ok(stamped)
}

/// The stamp's pooled connection, closed on drop unless its busy timeout was
/// restored: dropped mid-stamp by a cancelled request, it would otherwise
/// rejoin the pool without the wait. A restored one is returned, since closing
/// the last connection of an in-memory database would discard the database.
#[derive(Debug)]
struct StampConnection {
    connection: PoolConnection<Sqlite>,
    restored: bool,
}

impl Drop for StampConnection {
    /// Close the connection unless its busy timeout was restored.
    fn drop(&mut self) {
        if !self.restored {
            self.connection.close_on_drop();
        }
    }
}

/// Delete an API token by ID.
/// Reports `false` when no row had the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: TokenId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM api_tokens WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List the API tokens authenticating into a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<Sqlite>,
    role_id: RoleId,
) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tokens = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens WHERE role_id = ? ORDER BY created_at DESC, id DESC",
    )
    .bind(role_id)
    .fetch_all(&mut *connection)
    .await?;

    Ok(tokens)
}

#[cfg(test)]
mod tests;

/// List credential metadata with its role name, filtered and paged in SQL.
pub(crate) async fn list_by_filter_with_role(
    pool: &Pool<Sqlite>,
    filter: &ApiTokenFilter,
) -> Result<Vec<ApiTokenMetadata>, DatabaseError> {
    let mut connection = pool.acquire().await?;
    let result = sqlx::query_as::<_, ApiTokenMetadata>(
        r#"
        SELECT t.id, t.name, t.description, r.name AS role_name, t.created_at, t.expires_at, t.last_used_at
        FROM api_tokens t
        INNER JOIN roles r ON r.id = t.role_id
        WHERE (? IS NULL OR t.role_id = ?)
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT ?
        OFFSET ?
        "#,
    )
    .bind(filter.role_id)
    .bind(filter.role_id)
    .bind(filter.limit.map_or(i64::MAX, i64::from))
    .bind(filter.offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;
    Ok(result)
}

/// Count credentials matching the role filter, ignoring its page window.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    filter: &ApiTokenFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;
    let result = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM api_tokens t
        INNER JOIN roles r ON r.id = t.role_id
        WHERE (? IS NULL OR t.role_id = ?)
        "#,
    )
    .bind(filter.role_id)
    .bind(filter.role_id)
    .fetch_one(&mut *connection)
    .await?;
    Ok(result as u64)
}
