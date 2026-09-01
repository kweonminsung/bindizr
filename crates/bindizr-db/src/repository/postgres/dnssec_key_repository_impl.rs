use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
    repository::{DnssecKeyRepository, LockLevel, RepositoryTx, sql::lock_clause},
};

/// PostgreSQL-backed implementation of `DnssecKeyRepository`.
pub(crate) struct PostgresDnssecKeyRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnssecKeyRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecKeyRepository for PostgresDnssecKeyRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut key: DnssecKey,
    ) -> Result<DnssecKey, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let result = sqlx::query(
            r#"
            INSERT INTO dnssec_keys (zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
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
        .fetch_one(&mut **postgres_tx)
        .await?;

        key.id = result.get::<i32, _>(0);
        Ok(key)
    }

    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let keys = sqlx::query_as::<_, DnssecKey>(AssertSqlSafe(format!(
            "{}{}",
            r#"
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, ds_seen_at, max_signed_ttl, created_at
            FROM dnssec_keys
            WHERE zone_id = $1
            ORDER BY id
            "#,
            lock_clause(lock_level)
        )))
        .bind(zone_id)
        .fetch_all(&mut **postgres_tx)
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
            SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, ds_seen_at, max_signed_ttl, created_at
            FROM dnssec_keys
            WHERE state = $1 AND eligible_at <= $2
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

        let zone_ids = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT DISTINCT k.zone_id
            FROM dnssec_keys k
            JOIN zones z ON z.id = k.zone_id
            WHERE k.role = $1 AND k.state = $2
              AND COALESCE(z.dnssec_zsk_lifetime_days, $3) > 0
              AND k.state_changed_at
                  < $4 - make_interval(days => COALESCE(z.dnssec_zsk_lifetime_days, $3))
            ORDER BY k.zone_id
            "#,
        )
        .bind(role.as_str())
        .bind(state.as_str())
        .bind(default_zsk_lifetime_days as i32)
        .bind(now)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_ids)
    }

    async fn list_by_state(&self, state: DnssecKeyState) -> Result<Vec<DnssecKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let keys = sqlx::query_as::<_, DnssecKey>(
            "SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, ds_seen_at, max_signed_ttl, created_at FROM dnssec_keys WHERE state = $1 ORDER BY id",
        )
        .bind(state.as_str())
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    async fn update_ds_seen_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        ds_seen_at: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("UPDATE dnssec_keys SET ds_seen_at = $1, eligible_at = $2 WHERE id = $3")
            .bind(ds_seen_at)
            .bind(eligible_at)
            .bind(id)
            .execute(&mut **postgres_tx)
            .await?;

        Ok(())
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
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM dnssec_keys WHERE state = $1")
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
        let postgres_tx = tx.as_postgres()?;

        sqlx::query(
            "UPDATE dnssec_keys SET state = $1, state_changed_at = $2, eligible_at = $3 WHERE id = $4",
        )
        .bind(state.as_str())
        .bind(changed_at)
        .bind(eligible_at)
        .bind(id)
            .execute(&mut **postgres_tx)
            .await?;

        Ok(())
    }

    async fn update_max_signed_ttl_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        max_signed_ttl: i32,
    ) -> Result<(), DatabaseError> {
        let pg_tx = tx.as_postgres()?;

        sqlx::query("UPDATE dnssec_keys SET max_signed_ttl = $1 WHERE id = $2")
            .bind(max_signed_ttl)
            .bind(id)
            .execute(&mut **pg_tx)
            .await?;

        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("DELETE FROM dnssec_keys WHERE id = $1")
            .bind(id)
            .execute(&mut **postgres_tx)
            .await?;

        Ok(())
    }

    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("DELETE FROM dnssec_keys WHERE zone_id = $1")
            .bind(zone_id)
            .execute(&mut **postgres_tx)
            .await?;

        Ok(())
    }
}
