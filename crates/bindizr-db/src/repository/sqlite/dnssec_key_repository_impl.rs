use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
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
        .execute(&mut **sqlite_tx)
        .await?;

        key.id = result.last_insert_rowid() as i32;
        Ok(key)
    }

    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        _lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let keys = sqlx::query_as::<_, DnssecKey>(
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at
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

    async fn list_by_state_eligible_before(
        &self,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        // datetime(?) normalizes the bound value to the column's stored format.
        let keys = sqlx::query_as::<_, DnssecKey>(
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at
            FROM dnssec_keys
            WHERE state = ? AND eligible_at <= datetime(?)
            ORDER BY zone_id, id
            "#,
        )
        .bind(state.as_str())
        .bind(cutoff)
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    async fn list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
        &self,
        role: DnssecKeyRole,
        state: DnssecKeyState,
        now: DateTime<Utc>,
        default_zsk_lifetime_days: u32,
    ) -> Result<Vec<i32>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        // datetime() normalizes both sides to one stored format.
        let zone_ids = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT DISTINCT k.zone_id
            FROM dnssec_keys k
            JOIN zones z ON z.id = k.zone_id
            WHERE k.role = ? AND k.state = ?
              AND COALESCE(z.dnssec_zsk_lifetime_days, ?) > 0
              AND datetime(k.state_changed_at)
                  < datetime(?, '-' || COALESCE(z.dnssec_zsk_lifetime_days, ?) || ' days')
            ORDER BY k.zone_id
            "#,
        )
        .bind(role.as_str())
        .bind(state.as_str())
        .bind(default_zsk_lifetime_days as i32)
        .bind(now)
        .bind(default_zsk_lifetime_days as i32)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_ids)
    }

    async fn count_zone_ids(&self) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(DISTINCT zone_id) FROM dnssec_keys")
            .fetch_one(&mut *conn)
            .await?;

        Ok(count as u64)
    }

    async fn count_by_state(&self, state: DnssecKeyState) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM dnssec_keys WHERE state = ?")
                .bind(state.as_str())
                .fetch_one(&mut *conn)
                .await?;

        Ok(count as u64)
    }

    async fn update_state_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        state: DnssecKeyState,
        changed_at: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query(
            "UPDATE dnssec_keys SET state = ?, state_changed_at = ?, eligible_at = ? WHERE id = ?",
        )
        .bind(state.as_str())
        .bind(changed_at)
        .bind(eligible_at)
        .bind(id)
        .execute(&mut **sqlite_tx)
        .await?;

        Ok(())
    }

    async fn update_max_signed_ttl_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        max_signed_ttl: i32,
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("UPDATE dnssec_keys SET max_signed_ttl = ? WHERE id = ?")
            .bind(max_signed_ttl)
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
