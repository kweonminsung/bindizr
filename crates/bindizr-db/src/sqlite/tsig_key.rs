use bindizr_core::model::{role::RoleId, tsig_key::TsigKeyId};
use chrono::Utc;
use sqlx::{Pool, Sqlite};

use crate::{error::DatabaseError, model::tsig_key::TsigKey};

/// Insert a TSIG key.
pub(crate) async fn create(
    pool: &Pool<Sqlite>,
    mut key: TsigKey,
) -> Result<TsigKey, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO tsig_keys (name, algorithm, secret, role_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&key.name)
    .bind(key.algorithm.as_str())
    .bind(&key.secret)
    .bind(key.role_id)
    .bind(now)
    .execute(&mut *conn)
    .await?;

    key.id = TsigKeyId::from(result.last_insert_rowid() as i32);
    key.created_at = now;
    Ok(key)
}

/// Find a TSIG key by ID.
pub(crate) async fn get(
    pool: &Pool<Sqlite>,
    id: TsigKeyId,
) -> Result<Option<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(key)
}

/// Find a TSIG key by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(key)
}

/// List all TSIG keys.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let keys = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(keys)
}

/// Delete a TSIG key by ID.
pub(crate) async fn delete(pool: &Pool<Sqlite>, id: TsigKeyId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM tsig_keys WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Count the TSIG keys authenticating into a role: the in-use check before a role delete.
pub(crate) async fn count_by_role_id(
    pool: &Pool<Sqlite>,
    role_id: RoleId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tsig_keys WHERE role_id = ?")
        .bind(role_id)
        .fetch_one(&mut *conn)
        .await?;

    Ok(count as u64)
}
