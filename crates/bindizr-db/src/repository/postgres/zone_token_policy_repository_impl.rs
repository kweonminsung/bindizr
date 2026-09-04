use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::zone_token_policy::ZoneTokenPolicy,
    repository::{LockLevel, RepositoryTx, ZoneTokenPolicyRepository, sql::lock_clause},
};

pub(crate) struct PostgresZoneTokenPolicyRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneTokenPolicyRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneTokenPolicyRepository for PostgresZoneTokenPolicyRepository {
    async fn create(&self, mut policy: ZoneTokenPolicy) -> Result<ZoneTokenPolicy, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zone_token_policies (zone_id, api_token_id, record_name_pattern, record_types)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(policy.zone_id)
        .bind(policy.api_token_id)
        .bind(&policy.record_name_pattern)
        .bind(&policy.record_types)
        .fetch_one(&mut *conn)
        .await?;

        policy.id = result.get::<i32, _>(0);

        Ok(policy)
    }

    async fn get(&self, id: i32) -> Result<Option<ZoneTokenPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policy = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(policy)
    }

    async fn list(&self, zone_id: i32) -> Result<Vec<ZoneTokenPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policies = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE zone_id = $1 ORDER BY id",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(policies)
    }

    async fn list_by_zone_id_and_token_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneTokenPolicy>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let policies = sqlx::query_as::<_, ZoneTokenPolicy>(AssertSqlSafe(
            format!("SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE zone_id = $1 AND api_token_id = $2 ORDER BY id{}",
            lock_clause(lock_level),
        )))
        .bind(zone_id)
        .bind(api_token_id)
        .fetch_all(&mut **postgres_tx)
        .await?;

        Ok(policies)
    }

    async fn list_by_token_id(
        &self,
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policies = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE api_token_id = $1 ORDER BY id",
        )
        .bind(api_token_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(policies)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zone_token_policies WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
