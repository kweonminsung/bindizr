use bindizr_core::model::{role::RoleId, tsig_key::TsigKeyId};
use chrono::Utc;
use sqlx::{AssertSqlSafe, MySql, Pool, Transaction};

use crate::{LockLevel, error::DatabaseError, model::tsig_key::TsigKey};

/// Insert a TSIG key.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, MySql>,
    mut key: TsigKey,
) -> Result<TsigKey, DatabaseError> {
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
    .execute(&mut **tx)
    .await?;

    key.id = TsigKeyId::from(result.last_insert_id() as i32);
    key.created_at = now;

    Ok(key)
}

/// Find a TSIG key by ID.
pub(crate) async fn get(
    pool: &Pool<MySql>,
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

/// A TSIG key by id in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, MySql>,
    id: TsigKeyId,
    lock_level: LockLevel,
) -> Result<Option<TsigKey>, DatabaseError> {
    let row = sqlx::query_as::<_, TsigKey>(AssertSqlSafe(format!(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE id = ?{}",
        lock_level.clause(),
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row)
}

/// Find a TSIG key by name.
pub(crate) async fn get_by_name(
    pool: &Pool<MySql>,
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
pub(crate) async fn list_all(pool: &Pool<MySql>) -> Result<Vec<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let keys = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(keys)
}

/// Delete a TSIG key by ID.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, MySql>,
    id: TsigKeyId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM tsig_keys WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// List the TSIG keys authenticating into a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<MySql>,
    role_id: RoleId,
) -> Result<Vec<TsigKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE role_id = ? ORDER BY name",
    )
    .bind(role_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows)
}
