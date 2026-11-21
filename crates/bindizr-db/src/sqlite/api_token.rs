use bindizr_core::model::api_token::{ApiToken, TokenId};
use bindizr_core::model::role::RoleId;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite, Transaction};

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

/// List all API tokens.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<ApiToken>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tokens = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, token, description, role_id, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(&mut *connection)
    .await?;

    Ok(tokens)
}

/// Stamp when the token was last used, returning whether it was stamped. A
/// mutation holds the database writer for its whole transaction, so the stamp
/// gives up at once rather than wait for it: nothing may block on a stamp.
pub(crate) async fn update_last_used_at(
    pool: &Pool<Sqlite>,
    id: TokenId,
    last_used_at: DateTime<Utc>,
) -> Result<bool, DatabaseError> {
    let mut connection = pool.acquire().await?;

    // Closed rather than returned: dropped mid-stamp by a cancelled request,
    // it would otherwise rejoin the pool without its busy timeout.
    connection.close_on_drop();

    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&mut *connection)
        .await?;

    match sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
        .bind(last_used_at)
        .bind(id)
        .execute(&mut *connection)
        .await
    {
        Ok(result) => Ok(result.rows_affected() > 0),
        Err(sqlx::Error::Database(error)) if sqlite::is_busy(error.as_ref()) => Ok(false),
        Err(error) => Err(error.into()),
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
mod tests {
    use std::time::{Duration, Instant};

    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

    use super::*;
    use crate::schema;

    /// Verify that the stamp gives up rather than wait while another
    /// connection holds the database writer, stamps once it is free, and leaves
    /// no pooled connection without its busy timeout.
    #[tokio::test]
    async fn update_last_used_at_skips_a_held_writer() {
        let directory = tempfile::tempdir().unwrap();
        let options = SqliteConnectOptions::new()
            .filename(directory.path().join("stamp.sqlite"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query(sqlite::BUSY_TIMEOUT_PRAGMA)
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .unwrap();

        for query in schema::sqlite::table_creation_queries() {
            sqlx::query(query).execute(&pool).await.unwrap();
        }

        sqlx::query("INSERT INTO roles (id, name, created_at) VALUES (1, 'r', ?)")
            .bind(Utc::now())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO api_tokens (id, name, token, role_id, created_at) VALUES (1, 't', 'h', 1, ?)",
        )
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();

        let mut writer = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
        let started = Instant::now();

        assert!(
            !update_last_used_at(&pool, TokenId::from(1), Utc::now())
                .await
                .unwrap()
        );
        assert!(started.elapsed() < Duration::from_secs(5));

        sqlx::query("SELECT 1").execute(&mut *writer).await.unwrap();
        writer.rollback().await.unwrap();

        assert!(
            update_last_used_at(&pool, TokenId::from(1), Utc::now())
                .await
                .unwrap()
        );

        // The stamp's connection is closed, so every pooled one keeps the wait.
        for _ in 0..2 {
            let timeout = sqlx::query_scalar::<_, i64>("PRAGMA busy_timeout")
                .fetch_one(&pool)
                .await
                .unwrap();

            assert_eq!(timeout, 15000);
        }
    }
}
