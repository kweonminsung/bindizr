use bindizr_core::model::dnssec_policy::PolicyId;
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{LockLevel, error::DatabaseError, model::dnssec_policy::DnssecPolicy};

/// Insert a DNSSEC policy.
pub(crate) async fn create(
    pool: &Pool<Postgres>,
    mut policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO dnssec_policies (name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
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
    .fetch_one(&mut *conn)
    .await?;

    policy.id = PolicyId::from(result.get::<i32, _>(0));
    policy.created_at = now;
    Ok(policy)
}

/// Find a DNSSEC policy by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: PolicyId,
    lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(AssertSqlSafe(format!(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE id = $1{}",
        lock_level.clause()
    )))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// Find a DNSSEC policy by name.
pub(crate) async fn get_by_name(
    pool: &Pool<Postgres>,
    name: &str,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let policy = sqlx::query_as::<_, DnssecPolicy>(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    Ok(policy)
}

/// Find a DNSSEC policy by name in the current transaction.
pub(crate) async fn get_by_name_tx(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    lock_level: LockLevel,
) -> Result<Option<DnssecPolicy>, DatabaseError> {
    let policy = sqlx::query_as::<_, DnssecPolicy>(AssertSqlSafe(format!(
        "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, created_at FROM dnssec_policies WHERE name = $1{}",
        lock_level.clause()
    )))
    .bind(name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(policy)
}

/// List all DNSSEC policies.
pub(crate) async fn list_all(pool: &Pool<Postgres>) -> Result<Vec<DnssecPolicy>, DatabaseError> {
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
    tx: &mut Transaction<'_, Postgres>,
    policy: DnssecPolicy,
) -> Result<DnssecPolicy, DatabaseError> {
    sqlx::query(
        r#"
        UPDATE dnssec_policies
        SET signature_validity_days = $1, signature_refresh_days = $2, zsk_lifetime_days = $3
        WHERE id = $4
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
pub(crate) async fn delete(pool: &Pool<Postgres>, id: PolicyId) -> Result<(), DatabaseError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("DELETE FROM dnssec_policies WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;

    Ok(())
}
