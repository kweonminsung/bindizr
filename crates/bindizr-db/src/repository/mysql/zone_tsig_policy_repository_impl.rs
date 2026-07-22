use async_trait::async_trait;
use sqlx::{MySql, Pool};

use crate::{
    error::DatabaseError,
    model::zone_tsig_policy::ZoneTsigPolicy,
    repository::{RepositoryTx, RepositoryTxKind, ZoneTsigPolicyRepository},
};

/// MySQL-backed implementation of `ZoneTsigPolicyRepository`.
pub struct MySqlZoneTsigPolicyRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneTsigPolicyRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneTsigPolicyRepository for MySqlZoneTsigPolicyRepository {
    async fn create(&self, mut policy: ZoneTsigPolicy) -> Result<ZoneTsigPolicy, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zone_tsig_policies (zone_id, tsig_key_id, record_name_pattern, record_types)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(policy.zone_id)
        .bind(policy.tsig_key_id)
        .bind(&policy.record_name_pattern)
        .bind(&policy.record_types)
        .execute(&mut *conn)
        .await?;

        policy.id = result.last_insert_id() as i32;

        Ok(policy)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneTsigPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policy = sqlx::query_as::<_, ZoneTsigPolicy>(
            "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM zone_tsig_policies WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(policy)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneTsigPolicy>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let policies = sqlx::query_as::<_, ZoneTsigPolicy>(
            "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM zone_tsig_policies WHERE zone_id = ? ORDER BY id",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(policies)
    }

    async fn get_by_zone_and_key_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
    ) -> Result<Vec<ZoneTsigPolicy>, DatabaseError> {
        let mysql_tx = match &mut tx.0 {
            RepositoryTxKind::MySQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected MySQL)".to_string(),
                ));
            }
        };

        let policies = sqlx::query_as::<_, ZoneTsigPolicy>(
            "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM zone_tsig_policies WHERE zone_id = ? AND tsig_key_id = ? ORDER BY id",
        )
        .bind(zone_id)
        .bind(tsig_key_id)
        .fetch_all(&mut **mysql_tx)
        .await?;

        Ok(policies)
    }

    async fn count_by_key_id(&self, tsig_key_id: i32) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM zone_tsig_policies WHERE tsig_key_id = ?",
        )
        .bind(tsig_key_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zone_tsig_policies WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
