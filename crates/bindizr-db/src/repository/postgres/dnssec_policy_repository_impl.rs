use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::dnssec_policy::DnssecPolicy,
    repository::{DnssecPolicyRepository, LockLevel, RepositoryTx, sql::lock_clause},
};

/// Postgres-backed implementation of `DnssecPolicyRepository`.
pub(crate) struct PostgresDnssecPolicyRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnssecPolicyRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecPolicyRepository for PostgresDnssecPolicyRepository {
    async fn create(&self, mut policy: DnssecPolicy) -> Result<DnssecPolicy, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO dnssec_policies (name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, rollover_publish_holddown_secs, rollover_retire_holddown_secs)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
        .bind(policy.rollover_publish_holddown_secs)
        .bind(policy.rollover_retire_holddown_secs)
        .fetch_one(&mut *conn)
        .await?;

        policy.id = result.get::<i32, _>(0);
        Ok(policy)
    }

    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let policy = sqlx::query_as::<_, DnssecPolicy>(AssertSqlSafe(format!(
            "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, rollover_publish_holddown_secs, rollover_retire_holddown_secs, created_at FROM dnssec_policies WHERE id = $1{}",
            lock_clause(lock_level)
        )))
        .bind(id)
        .fetch_optional(&mut **postgres_tx)
        .await?;

        Ok(policy)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<DnssecPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policy = sqlx::query_as::<_, DnssecPolicy>(
            "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, rollover_publish_holddown_secs, rollover_retire_holddown_secs, created_at FROM dnssec_policies WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(policy)
    }

    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let policy = sqlx::query_as::<_, DnssecPolicy>(AssertSqlSafe(format!(
            "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, rollover_publish_holddown_secs, rollover_retire_holddown_secs, created_at FROM dnssec_policies WHERE name = $1{}",
            lock_clause(lock_level)
        )))
        .bind(name)
        .fetch_optional(&mut **postgres_tx)
        .await?;

        Ok(policy)
    }

    async fn list_all(&self) -> Result<Vec<DnssecPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policies = sqlx::query_as::<_, DnssecPolicy>(
            "SELECT id, name, algorithm, denial, split_keys, signature_validity_days, signature_refresh_days, zsk_lifetime_days, rollover_publish_holddown_secs, rollover_retire_holddown_secs, created_at FROM dnssec_policies ORDER BY name",
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(policies)
    }

    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        policy: DnssecPolicy,
    ) -> Result<DnssecPolicy, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query(
            r#"
            UPDATE dnssec_policies
            SET signature_validity_days = $1, signature_refresh_days = $2, zsk_lifetime_days = $3,
                rollover_publish_holddown_secs = $4, rollover_retire_holddown_secs = $5
            WHERE id = $6
            "#,
        )
        .bind(policy.signature_validity_days)
        .bind(policy.signature_refresh_days)
        .bind(policy.zsk_lifetime_days)
        .bind(policy.rollover_publish_holddown_secs)
        .bind(policy.rollover_retire_holddown_secs)
        .bind(policy.id)
        .execute(&mut **postgres_tx)
        .await?;

        Ok(policy)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM dnssec_policies WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
