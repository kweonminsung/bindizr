use bindizr_core::model::dnssec_policy::PolicyId;
use chrono::Utc;
use sqlx::{Pool, Sqlite, Transaction};

use crate::{LockLevel, error::DatabaseError, model::dnssec_policy::DnssecPolicy};

/// Insert a DNSSEC policy.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    mut policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO dnssec_policies (name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&policy.name)
    .bind(policy.algorithm.to_int())
    .bind(policy.denial.as_str())
    .bind(policy.split_keys)
    .bind(policy.signature_validity_days)
    .bind(policy.signature_refresh_days)
    .bind(policy.zsk_lifetime_days)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    policy.id = PolicyId::from(result.last_insert_rowid() as i32);
    policy.created_at = now;
    Ok(policy)
}

/// Find a DNSSEC policy by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: PolicyId,
    _lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// Find a DNSSEC policy by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Sqlite>,
    name: &str,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(policy)
}

/// Find a DNSSEC policy by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
    _lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// List all DNSSEC policies.
pub(crate) async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<DnssecPolicy>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let policies = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(policies)
}

/// Update a DNSSEC policy in the current transaction.
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
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: PolicyId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM dnssec_policies WHERE id = ?")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}
