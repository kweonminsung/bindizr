use bindizr_core::{
    dns::address::AddressTarget,
    model::{secondary::SecondaryId, tsig_key::TsigKeyId},
};
use chrono::Utc;
use sqlx::{Pool, Sqlite, Transaction};

use crate::{LockLevel, error::DatabaseError, model::secondary::Secondary};

/// Insert a secondary.
pub(crate) async fn create(
    pool: &Pool<Sqlite>,
    mut secondary: Secondary,
) -> Result<Secondary, DatabaseError> {
    let mut conn = pool.acquire().await?;

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
    .execute(&mut *conn)
    .await?;

    secondary.id = SecondaryId::from(result.last_insert_rowid() as i32);
    secondary.created_at = now;
    Ok(secondary)
}

/// Find a secondary by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<Secondary>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(secondary)
}

/// Find a secondary by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    _lock_level: LockLevel,
) -> Result<Option<Secondary>, DatabaseError> {
    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(secondary)
}

/// Find a secondary by address.
pub(crate) async fn get_by_address(
    pool: &Pool<Sqlite>,
    address: &AddressTarget,
) -> Result<Option<Secondary>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE address = ?",
    )
    .bind(address)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(secondary)
}

/// List all secondaries, disabled ones included.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<Secondary>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let secondaries = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(secondaries)
}

/// Write the address and enabled flag; the name is fixed at creation.
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

/// Secondaries whose NOTIFY the key signs: the in-use check before a key
/// delete.
pub(crate) async fn count_by_notify_tsig_key_id(
    pool: &Pool<Sqlite>,
    tsig_key_id: TsigKeyId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM secondaries WHERE notify_tsig_key_id = ?",
    )
    .bind(tsig_key_id)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}

/// Delete a secondary by ID.
pub(crate) async fn delete(pool: &Pool<Sqlite>, id: SecondaryId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM secondaries WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
