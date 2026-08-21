use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::dnssec_key::{DnssecKey, DnssecKeyState},
    repository::{DnssecKeyRepository, LockLevel, RepositoryTx},
};

/// SQLite-backed implementation of `DnssecKeyRepository`.
pub(crate) struct SqliteDnssecKeyRepository {
    pool: Pool<Sqlite>,
}

impl SqliteDnssecKeyRepository {
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecKeyRepository for SqliteDnssecKeyRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut key: DnssecKey,
    ) -> Result<DnssecKey, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let result = sqlx::query(
            r#"
            INSERT INTO dnssec_keys (zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        .execute(&mut **sqlite_tx)
        .await?;

        key.id = result.last_insert_rowid() as i32;
        Ok(key)
    }

    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<DnssecKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let keys = sqlx::query_as::<_, DnssecKey>(
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, created_at
            FROM dnssec_keys
            WHERE zone_id = ?
            ORDER BY id
            "#,
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    async fn list_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        _lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let keys = sqlx::query_as::<_, DnssecKey>(
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, created_at
            FROM dnssec_keys
            WHERE zone_id = ?
            ORDER BY id
            "#,
        )
        .bind(zone_id)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(keys)
    }

    async fn list_by_state_entered_before(
        &self,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        // datetime(?) normalizes the bound value to the column's stored format.
        let keys = sqlx::query_as::<_, DnssecKey>(
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, created_at
            FROM dnssec_keys
            WHERE state = ? AND state_changed_at < datetime(?)
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
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("UPDATE dnssec_keys SET state = ?, state_changed_at = ? WHERE id = ?")
            .bind(state.as_str())
            .bind(changed_at)
            .bind(id)
            .execute(&mut **sqlite_tx)
            .await?;

        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("DELETE FROM dnssec_keys WHERE id = ?")
            .bind(id)
            .execute(&mut **sqlite_tx)
            .await?;

        Ok(())
    }

    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("DELETE FROM dnssec_keys WHERE zone_id = ?")
            .bind(zone_id)
            .execute(&mut **sqlite_tx)
            .await?;

        Ok(())
    }
}
