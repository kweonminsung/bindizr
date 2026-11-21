use bindizr_core::dns::address::AddressTarget;
use bindizr_core::model::secondary::{Secondary, SecondaryId, SecondaryWithNotifyKey};
use bindizr_core::model::tsig_key::TsigKeyId;
use chrono::Utc;
use sqlx::{Pool, Sqlite, Transaction};

use crate::error::DatabaseError;
use crate::sqlite;

/// Insert a secondary.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    mut secondary: Secondary,
) -> Result<Secondary, DatabaseError> {
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO secondaries (name, address, enabled, notify_tsig_key_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&secondary.name)
    .bind(&secondary.address)
    .bind(secondary.enabled)
    .bind(secondary.notify_tsig_key_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    secondary.id = SecondaryId::from(sqlite::last_insert_id(&result)?);
    secondary.created_at = now;

    Ok(secondary)
}

/// Get a secondary by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<Secondary>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(secondary)
}

/// Get a secondary by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<Option<Secondary>, DatabaseError> {
    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(secondary)
}

/// Get a secondary by address.
pub(crate) async fn get_by_address(
    pool: &Pool<Sqlite>,
    address: &AddressTarget,
) -> Result<Option<Secondary>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE address = ?",
    )
    .bind(address)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(secondary)
}

/// List all secondaries, disabled ones included.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<Secondary>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let secondaries = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries ORDER BY name",
    )
    .fetch_all(&mut *connection)
    .await?;

    Ok(secondaries)
}

/// Write the address, enabled flag and NOTIFY signing key; the name is fixed
/// at creation.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Sqlite>,
    secondary: Secondary,
) -> Result<Secondary, DatabaseError> {
    sqlx::query(
        "UPDATE secondaries SET address = ?, enabled = ?, notify_tsig_key_id = ? WHERE id = ?",
    )
    .bind(&secondary.address)
    .bind(secondary.enabled)
    .bind(secondary.notify_tsig_key_id)
    .bind(secondary.id)
    .execute(&mut **tx)
    .await?;

    Ok(secondary)
}

/// Count the secondaries whose NOTIFY the key signs: the in-use check before a
/// key delete.
pub(crate) async fn count_by_notify_tsig_key_id(
    pool: &Pool<Sqlite>,
    notify_tsig_key_id: TsigKeyId,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM secondaries WHERE notify_tsig_key_id = ?",
    )
    .bind(notify_tsig_key_id)
    .fetch_one(&mut *connection)
    .await?;

    Ok(count as u64)
}

/// Delete a secondary by ID.
/// Reports `false` when no row had the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: SecondaryId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM secondaries WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List secondaries with their NOTIFY key names in name order, applying the supplied window.
pub(crate) async fn list_all_with_notify_tsig_key(
    pool: &Pool<Sqlite>,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<SecondaryWithNotifyKey>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let secondaries = sqlx::query_as::<_, SecondaryWithNotifyKey>(
        r#"
        SELECT s.id, s.name, s.address, s.enabled, s.notify_tsig_key_id, s.created_at, k.name AS notify_key_name
        FROM secondaries s
        LEFT JOIN tsig_keys k ON k.id = s.notify_tsig_key_id
        ORDER BY s.name
        LIMIT ?
        OFFSET ?
        "#,
    )
    .bind(limit.map_or(i64::MAX, i64::from))
    .bind(offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;

    Ok(secondaries)
}

/// Count all registered secondaries.
pub(crate) async fn count_all(pool: &Pool<Sqlite>) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM secondaries"#)
        .fetch_one(&mut *connection)
        .await?;

    Ok(count as u64)
}
