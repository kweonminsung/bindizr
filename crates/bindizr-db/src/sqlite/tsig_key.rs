use bindizr_core::model::role::RoleId;
use bindizr_core::model::tsig_key::{TsigKey, TsigKeyId, TsigKeyMetadata};
use chrono::Utc;
use sqlx::{Pool, Sqlite, Transaction};

use crate::error::DatabaseError;
use crate::tsig_key::TsigKeyFilter;
use crate::{LockLevel, sqlite};

/// Insert a TSIG key.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    mut tsig_key: TsigKey,
) -> Result<TsigKey, DatabaseError> {
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO tsig_keys (name, algorithm, secret, role_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&tsig_key.name)
    .bind(tsig_key.algorithm.as_str())
    .bind(&tsig_key.secret)
    .bind(tsig_key.role_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    tsig_key.id = TsigKeyId::from(sqlite::last_insert_id(&result)?);
    tsig_key.created_at = now;

    Ok(tsig_key)
}

/// Get a TSIG key by ID.
pub(crate) async fn get(
    pool: &Pool<Sqlite>,
    id: TsigKeyId,
) -> Result<Option<TsigKey>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tsig_key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(tsig_key)
}

/// Get a TSIG key by ID in the current transaction, locked at `lock_level`.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: TsigKeyId,
    _lock_level: LockLevel,
) -> Result<Option<TsigKey>, DatabaseError> {
    let tsig_key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(tsig_key)
}

/// Get a TSIG key by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<TsigKey>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tsig_key = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(tsig_key)
}

/// Delete a TSIG key by ID.
/// Reports `false` when no row had the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: TsigKeyId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM tsig_keys WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List the TSIG keys authenticating into a role.
pub(crate) async fn list_by_role_id(
    pool: &Pool<Sqlite>,
    role_id: RoleId,
) -> Result<Vec<TsigKey>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let tsig_keys = sqlx::query_as::<_, TsigKey>(
        "SELECT id, name, algorithm, secret, role_id, created_at FROM tsig_keys WHERE role_id = ? ORDER BY name",
    )
    .bind(role_id)
    .fetch_all(&mut *connection)
    .await?;

    Ok(tsig_keys)
}

/// List credential metadata with its role name, filtered and paged in SQL.
pub(crate) async fn list_by_filter_with_role(
    pool: &Pool<Sqlite>,
    filter: &TsigKeyFilter,
) -> Result<Vec<TsigKeyMetadata>, DatabaseError> {
    let mut connection = pool.acquire().await?;
    let result = sqlx::query_as::<_, TsigKeyMetadata>(
        r#"
        SELECT t.id, t.name, t.algorithm, r.name AS role_name, t.created_at
        FROM tsig_keys t
        INNER JOIN roles r ON r.id = t.role_id
        WHERE (? IS NULL OR t.role_id = ?)
        ORDER BY t.name
        LIMIT ?
        OFFSET ?
        "#,
    )
    .bind(filter.role_id)
    .bind(filter.role_id)
    .bind(filter.limit.map_or(i64::MAX, i64::from))
    .bind(
        filter
            .offset
            .map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)),
    )
    .fetch_all(&mut *connection)
    .await?;
    Ok(result)
}

/// Count credentials matching the role filter, ignoring its page window.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    filter: &TsigKeyFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;
    let result = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM tsig_keys t
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
