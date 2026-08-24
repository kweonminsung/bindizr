use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::dnssec_key::{DnssecKey, DnssecKeyState},
    repository::{DnssecKeyRepository, LockLevel, RepositoryTx, sql::lock_clause},
};

/// MySQL-backed implementation of `DnssecKeyRepository`.
pub(crate) struct MySqlDnssecKeyRepository {
    pool: Pool<MySql>,
}

impl MySqlDnssecKeyRepository {
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecKeyRepository for MySqlDnssecKeyRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut key: DnssecKey,
    ) -> Result<DnssecKey, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let result = sqlx::query(
            r#"
            INSERT INTO dnssec_keys (zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(key.zone_id)
        .bind(key.role.as_str())
        .bind(key.algorithm.to_int())
        .bind(key.key_tag)
        .bind(&key.public_key)
        .bind(&key.private_key)
        .bind(key.state.as_str())
        .bind(key.state_changed_at)
        .bind(key.eligible_at)
        .bind(key.max_signed_ttl)
        .execute(&mut **mysql_tx)
        .await?;

        key.id = result.last_insert_id() as i32;
        Ok(key)
    }

    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let keys = sqlx::query_as::<_, DnssecKey>(AssertSqlSafe(format!(
            "{}{}",
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at
            FROM dnssec_keys
            WHERE zone_id = ?
            ORDER BY id
            "#,
            lock_clause(lock_level)
        )))
        .bind(zone_id)
        .fetch_all(&mut **mysql_tx)
        .await?;

        Ok(keys)
    }

    async fn list_by_state_eligible_before(
        &self,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let keys = sqlx::query_as::<_, DnssecKey>(
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at
            FROM dnssec_keys
            WHERE state = ? AND eligible_at <= ?
            ORDER BY zone_id, id
            "#,
        )
        .bind(state.as_str())
        .bind(cutoff)
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    async fn update_state_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        state: DnssecKeyState,
        changed_at: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query(
            "UPDATE dnssec_keys SET state = ?, state_changed_at = ?, eligible_at = ? WHERE id = ?",
        )
        .bind(state.as_str())
        .bind(changed_at)
        .bind(eligible_at)
        .bind(id)
        .execute(&mut **mysql_tx)
        .await?;

        Ok(())
    }

    async fn update_max_signed_ttl_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        max_signed_ttl: i32,
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query("UPDATE dnssec_keys SET max_signed_ttl = ? WHERE id = ?")
            .bind(max_signed_ttl)
            .bind(id)
            .execute(&mut **mysql_tx)
            .await?;

        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query("DELETE FROM dnssec_keys WHERE id = ?")
            .bind(id)
            .execute(&mut **mysql_tx)
            .await?;

        Ok(())
    }

    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query("DELETE FROM dnssec_keys WHERE zone_id = ?")
            .bind(zone_id)
            .execute(&mut **mysql_tx)
            .await?;

        Ok(())
    }
}
