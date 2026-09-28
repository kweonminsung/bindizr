use chrono::Utc;
use sqlx::{MySql, Pool};

use crate::{error::DatabaseError, model::tsig_key::TsigKey};

/// Insert a TSIG key.
pub(crate) async fn create(pool: &Pool<MySql>, mut key: TsigKey) -> Result<TsigKey, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO tsig_keys (name, algorithm, secret, is_global, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&key.name)
    .bind(key.algorithm.as_str())
    .bind(&key.secret)
    .bind(key.is_global)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    key.id = result.last_insert_id() as i32;
    key.created_at = now;

    Ok(key)
}

/// Find a TSIG key by ID.
pub(crate) async fn get(pool: &Pool<MySql>, id: i32) -> Result<Option<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, is_global, created_at FROM tsig_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(key)
}

/// Find a TSIG key by name.
pub(crate) async fn get_by_name(
    pool: &Pool<MySql>,
    name: &str,
) -> Result<Option<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, is_global, created_at FROM tsig_keys WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(key)
}

/// List all TSIG keys.
pub(crate) async fn list_all(pool: &Pool<MySql>) -> Result<Vec<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let keys = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, is_global, created_at FROM tsig_keys ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(keys)
}

/// Delete a TSIG key by ID.
pub(crate) async fn delete(pool: &Pool<MySql>, id: i32) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM tsig_keys WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
