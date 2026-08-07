use async_trait::async_trait;
use sqlx::{MySql, Pool};

use crate::{
    error::DatabaseError,
    model::zone_token_policy::ZoneTokenPolicy,
    repository::{RepositoryTx, ZoneTokenPolicyRepository},
};

/// MySQL-backed implementation of `ZoneTokenPolicyRepository`.
pub struct MySqlZoneTokenPolicyRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneTokenPolicyRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneTokenPolicyRepository for MySqlZoneTokenPolicyRepository {
    async fn create(&self, mut policy: ZoneTokenPolicy) -> Result<ZoneTokenPolicy, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zone_token_policies (zone_id, api_token_id, record_name_pattern, record_types)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(policy.zone_id)
        .bind(policy.api_token_id)
        .bind(&policy.record_name_pattern)
        .bind(&policy.record_types)
        .execute(&mut *conn)
        .await?;

        policy.id = result.last_insert_id() as i32;

        Ok(policy)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneTokenPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policy = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(policy)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneTokenPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policies = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE zone_id = ? ORDER BY id",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(policies)
    }

    async fn get_by_zone_and_token_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let policies = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE zone_id = ? AND api_token_id = ? ORDER BY id",
        )
        .bind(zone_id)
        .bind(api_token_id)
        .fetch_all(&mut **mysql_tx)
        .await?;

        Ok(policies)
    }

    async fn get_by_token_id(
        &self,
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policies = sqlx::query_as::<_, ZoneTokenPolicy>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM zone_token_policies WHERE api_token_id = ? ORDER BY id",
        )
        .bind(api_token_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(policies)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zone_token_policies WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
