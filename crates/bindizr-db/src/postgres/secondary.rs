use bindizr_core::model::{secondary::SecondaryId, tsig_key::TsigKeyId};
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{LockLevel, error::DatabaseError, model::secondary::Secondary};

/// Insert a secondary.
pub(crate) async fn create(
    pool: &Pool<Postgres>,
    mut secondary: Secondary,
) -> Result<Secondary, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO secondaries (name, address, enabled, notify_tsig_key_id, created_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
    )
    .bind(&secondary.name)
    .bind(&secondary.address)
    .bind(secondary.enabled)
    .bind(secondary.notify_tsig_key_id)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;

    secondary.id = SecondaryId::from(result.get::<i32, _>(0));
    secondary.created_at = now;
    Ok(secondary)
}

/// Find a secondary by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Postgres>,
    name: &str,
) -> Result<Option<Secondary>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(secondary)
}

/// Find a secondary by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    lock_level: LockLevel,
) -> Result<Option<Secondary>, DatabaseError> {
    let secondary = sqlx::query_as::<_, Secondary>(AssertSqlSafe(format!(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE name = $1{}",
        lock_level.clause()
    )))
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(secondary)
}

/// Find a secondary by address.
pub(crate) async fn get_by_address(
    pool: &Pool<Postgres>,
    address: &str,
) -> Result<Option<Secondary>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let secondary = sqlx::query_as::<_, Secondary>(
        "SELECT id, name, address, enabled, notify_tsig_key_id, created_at FROM secondaries WHERE address = $1",
    )
    .bind(address)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(secondary)
}

/// List all secondaries, disabled ones included.
pub(crate) async fn list_all(pool: &Pool<Postgres>) -> Result<Vec<Secondary>, DatabaseError> {
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
    tx: &mut Transaction<'_, Postgres>,
    secondary: Secondary,
) -> Result<Secondary, DatabaseError> {
    sqlx::query(
        "UPDATE secondaries SET address = $1, enabled = $2, notify_tsig_key_id = $3 WHERE id = $4",
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
    pool: &Pool<Postgres>,
    tsig_key_id: TsigKeyId,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM secondaries WHERE notify_tsig_key_id = $1",
    )
    .bind(tsig_key_id)
    .fetch_one(&mut *conn)
    .await?;

    Ok(count as u64)
}

/// Delete a secondary by ID.
pub(crate) async fn delete(pool: &Pool<Postgres>, id: SecondaryId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM secondaries WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
