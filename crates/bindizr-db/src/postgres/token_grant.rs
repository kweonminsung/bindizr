use bindizr_core::model::{api_token::TokenId, token_grant::TokenGrantId, zone::ZoneId};
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{LockLevel, error::DatabaseError, model::token_grant::TokenGrant};

/// Insert a token grant.
pub(crate) async fn create(
    pool: &Pool<Postgres>,
    mut grant: TokenGrant,
) -> Result<TokenGrant, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO token_grants (zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
    )
    .bind(grant.zone_id)
    .bind(grant.api_token_id)
    .bind(&grant.record_name_pattern)
    .bind(&grant.record_types)
    .bind(grant.can_write)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;

    grant.id = TokenGrantId::from(result.get::<i32, _>(0));
    grant.created_at = now;

    Ok(grant)
}

/// Find a token grant by ID.
pub(crate) async fn get(
    pool: &Pool<Postgres>,
    id: TokenGrantId,
) -> Result<Option<TokenGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grant = sqlx::query_as::<_, TokenGrant>(
        "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(grant)
}

/// List token grants for a zone.
pub(crate) async fn list_by_zone_id(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, TokenGrant>(
        "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE zone_id = $1 ORDER BY id",
    )
    .bind(zone_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// List token grants for an API token in a zone in the current transaction.
pub(crate) async fn list_by_zone_id_and_token_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    api_token_id: TokenId,
    lock_level: LockLevel,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    let grants = sqlx::query_as::<_, TokenGrant>(AssertSqlSafe(
        format!("SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE zone_id = $1 AND api_token_id = $2 ORDER BY id{}",
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
    pool: &Pool<Postgres>,
    api_token_id: TokenId,
) -> Result<Vec<TokenGrant>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let grants = sqlx::query_as::<_, TokenGrant>(
        "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, can_write, created_at FROM token_grants WHERE api_token_id = $1 ORDER BY id",
    )
    .bind(api_token_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(grants)
}

/// Delete a token grant by ID.
pub(crate) async fn delete(pool: &Pool<Postgres>, id: TokenGrantId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM token_grants WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Delete every grant a token holds in one zone, returning how many rows went.
pub(crate) async fn delete_by_token_id_and_zone_id(
    pool: &Pool<Postgres>,
    api_token_id: TokenId,
    zone_id: ZoneId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let result = sqlx::query("DELETE FROM token_grants WHERE api_token_id = $1 AND zone_id = $2")
        .bind(api_token_id)
        .bind(zone_id)
        .execute(&mut *conn)
        .await?;

    Ok(result.rows_affected())
}
