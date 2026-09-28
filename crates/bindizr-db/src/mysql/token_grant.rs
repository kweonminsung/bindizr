use chrono::Utc;
use sqlx::{AssertSqlSafe, MySql, Pool, Transaction};

use crate::{LockLevel, error::DatabaseError, model::token_grant::TokenGrant};

/// Insert a token grant.
pub(crate) async fn create(
    pool: &Pool<MySql>,
    mut grant: TokenGrant,
) -> Result<TokenGrant, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO token_grants (zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(grant.zone_id)
    .bind(grant.api_token_id)
    .bind(&grant.record_name_pattern)
    .bind(&grant.record_types)
    .bind(grant.can_write)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    grant.id = result.last_insert_id() as i32;
    grant.created_at = now;

    Ok(grant)
}

/// Find a token grant by ID.
pub(crate) async fn get(pool: &Pool<MySql>, id: i32) -> Result<Option<TokenGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grant = sqlx::query_as::<_, TokenGrant>(
        "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(grant)
}

/// List token grants for a zone.
pub(crate) async fn list_by_zone_id(
    pool: &Pool<MySql>,
    zone_id: i32,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, TokenGrant>(
        "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE zone_id = ? ORDER BY id",
    )
    .bind(zone_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// List token grants for an API token in a zone in the current transaction.
pub(crate) async fn list_by_zone_id_and_token_id_tx(
    tx: &mut Transaction<'_, MySql>,
    zone_id: i32,
    api_token_id: i32,
    lock_level: LockLevel,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    let grants = sqlx::query_as::<_, TokenGrant>(AssertSqlSafe(
        format!("SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE zone_id = ? AND api_token_id = ? ORDER BY id{}",
        lock_level.clause(),
    )))
    .bind(zone_id)
    .bind(api_token_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(grants)
}

/// List token grants for an API token.
pub(crate) async fn list_by_token_id(
    pool: &Pool<MySql>,
    api_token_id: i32,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, TokenGrant>(
        "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE api_token_id = ? ORDER BY id",
    )
    .bind(api_token_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// Delete a token grant by ID.
pub(crate) async fn delete(pool: &Pool<MySql>, id: i32) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM token_grants WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Delete every grant a token holds in one zone, returning how many rows went.
pub(crate) async fn delete_by_token_id_and_zone_id(
    pool: &Pool<MySql>,
    api_token_id: i32,
    zone_id: i32,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let result = sqlx::query("DELETE FROM token_grants WHERE api_token_id = ? AND zone_id = ?")
        .bind(api_token_id)
        .bind(zone_id)
        .execute(&mut *conn)
        .await?;

    Ok(result.rows_affected())
}
