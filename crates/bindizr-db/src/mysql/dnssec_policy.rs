use chrono::Utc;
use sqlx::{AssertSqlSafe, MySql, Pool, Transaction};

use crate::{LockLevel, error::DatabaseError, model::dnssec_policy::DnssecPolicy};

/// Insert a DNSSEC policy.
pub(crate) async fn create(
    pool: &Pool<MySql>,
    mut policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    let mut conn = pool.acquire().await?;

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
    .execute(&mut *conn)
    .await?;

    policy.id = result.last_insert_id() as i32;
    policy.created_at = now;
    Ok(policy)
}

/// Find a DNSSEC policy by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, MySql>,
    id: i32,
    lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(AssertSqlSafe(format!(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE id = ?{}",
        lock_level.clause()
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// Find a DNSSEC policy by name.
pub(crate) async fn get_by_name(
    pool: &Pool<MySql>,
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
    tx: &mut Transaction<'_, MySql>,
    name: &str,
    lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(AssertSqlSafe(format!(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = ?{}",
        lock_level.clause()
    )))
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// List all DNSSEC policies.
pub(crate) async fn list_all(pool: &Pool<MySql>) -> Result<Vec<DnssecPolicy>, DatabaseError> {
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
    tx: &mut Transaction<'_, MySql>,
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
pub(crate) async fn delete(pool: &Pool<MySql>, id: i32) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM dnssec_policies WHERE id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
