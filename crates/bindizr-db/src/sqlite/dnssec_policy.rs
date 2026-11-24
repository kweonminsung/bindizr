use bindizr_core::model::dnssec_policy::{DnssecPolicy, PolicyId};
use chrono::Utc;
use sqlx::{Pool, Sqlite, Transaction};

use crate::error::DatabaseError;
use crate::{LockLevel, sqlite};

/// Insert a DNSSEC policy.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    mut policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    let now = Utc::now();

    let result = sqlx::query(
        r#"
        INSERT INTO dnssec_policies (name, algorithm, denial, key_layout, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&policy.name)
    .bind(policy.algorithm.as_i32())
    .bind(policy.denial.as_str())
    .bind(policy.key_layout.as_str())
    .bind(policy.signature_validity_days)
    .bind(policy.signature_refresh_days)
    .bind(policy.zsk_lifetime_days)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    policy.id = PolicyId::from(sqlite::last_insert_id(&result)?);
    policy.created_at = now;

    Ok(policy)
}

/// Get a DNSSEC policy by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    policy_id: PolicyId,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, key_layout, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE id = ?",
    )
    .bind(policy_id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// Get a DNSSEC policy by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, key_layout, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *connection)
    .await?;

    Ok(policy)
}

/// Get a DNSSEC policy by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    _lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, key_layout, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// Write the editable timing fields; the key layout, algorithm, and denial mode
/// are fixed at creation.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Sqlite>,
    policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    sqlx::query(
        r#"
        UPDATE dnssec_policies
        SET signature_validity_days = ?, signature_refresh_days = ?, zsk_lifetime_days = ?
        WHERE id = ?
        "#,
    )
    .bind(policy.signature_validity_days)
    .bind(policy.signature_refresh_days)
    .bind(policy.zsk_lifetime_days)
    .bind(policy.id)
    .execute(&mut **tx)
    .await?;

    Ok(policy)
}

/// Delete a DNSSEC policy by ID.
/// Reports `false` when no row had the id.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    policy_id: PolicyId,
) -> Result<bool, DatabaseError> {
    let result = sqlx::query("DELETE FROM dnssec_policies WHERE id = ?")
        .bind(policy_id)
        .execute(&mut **tx)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// List DNSSEC policies in name order, applying the supplied window.
pub(crate) async fn list_all(
    pool: &Pool<Sqlite>,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<DnssecPolicy>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let policies = sqlx::query_as::<_, DnssecPolicy>(
        r#"
        SELECT id, name, algorithm, denial, key_layout, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at
        FROM dnssec_policies
        ORDER BY name
        LIMIT ?
        OFFSET ?
        "#,
    )
    .bind(limit.map_or(i64::MAX, i64::from))
    .bind(offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;

    Ok(policies)
}

/// Count all DNSSEC policies.
pub(crate) async fn count_all(pool: &Pool<Sqlite>) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM dnssec_policies"#)
        .fetch_one(&mut *connection)
        .await?;

    Ok(count as u64)
}
