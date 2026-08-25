use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::zone_version::ZoneVersion,
    repository::{LockLevel, RepositoryTx, ZoneVersionRepository, sql::lock_clause},
};

/// Hides serials whose journal carries only signer-generated changes
/// (re-signs, rollovers). Serials with user changes, serials with no journal
/// at all (zone creation, forced bumps), and the current serial stay listed.
const USER_CHANGES_FILTER: &str = r#"
              AND (
                  zone_versions.serial = (SELECT zones.serial FROM zones WHERE zones.id = zone_versions.zone_id)
                  OR EXISTS (
                      SELECT 1 FROM zone_journal
                      WHERE zone_journal.zone_id = zone_versions.zone_id
                        AND zone_journal.serial = zone_versions.serial
                        AND zone_journal.derived = FALSE
                  )
                  OR NOT EXISTS (
                      SELECT 1 FROM zone_journal
                      WHERE zone_journal.zone_id = zone_versions.zone_id
                        AND zone_journal.serial = zone_versions.serial
                  )
              )"#;

/// PostgreSQL-backed implementation of `ZoneVersionRepository`.
pub(crate) struct PostgresZoneVersionRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneVersionRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneVersionRepository for PostgresZoneVersionRepository {
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query_as::<_, ZoneVersion>(
            r#"
            INSERT INTO zone_versions (zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (zone_id, serial)
            DO UPDATE SET
                mname = EXCLUDED.mname,
                rname = EXCLUDED.rname,
                default_ttl = EXCLUDED.default_ttl,
                refresh = EXCLUDED.refresh,
                retry = EXCLUDED.retry,
                expire = EXCLUDED.expire,
                minimum_ttl = EXCLUDED.minimum_ttl
            RETURNING id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            "#,
        )
        .bind(version.zone_id)
        .bind(version.serial)
        .bind(&version.mname)
        .bind(&version.rname)
        .bind(version.default_ttl)
        .bind(version.refresh)
        .bind(version.retry)
        .bind(version.expire)
        .bind(version.minimum_ttl)
        .fetch_one(&mut **postgres_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_by_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, DatabaseError> {
        sqlx::query_as::<_, ZoneVersion>(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = $1 AND serial = $2
            "#,
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn list_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, DatabaseError> {
        sqlx::query_as::<_, ZoneVersion>(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = $1 AND serial >= $2 AND serial <= $3
            "#,
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
    async fn list(
        &self,
        zone_id: i32,
        user_changes_only: bool,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneVersion>, DatabaseError> {
        let filter = if user_changes_only {
            USER_CHANGES_FILTER
        } else {
            ""
        };
        sqlx::query_as::<_, ZoneVersion>(AssertSqlSafe(format!(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = $1{filter}
            ORDER BY serial DESC
            LIMIT $2 OFFSET $3
            "#
        )))
        .bind(zone_id)
        .bind(limit as i64)
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn count(&self, zone_id: i32, user_changes_only: bool) -> Result<u64, DatabaseError> {
        let filter = if user_changes_only {
            USER_CHANGES_FILTER
        } else {
            ""
        };
        let count: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM zone_versions WHERE zone_id = $1{filter}"
        )))
        .bind(zone_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        Ok(count as u64)
    }

    async fn get_by_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneVersion>, DatabaseError> {
        let pg_tx = tx.as_postgres()?;

        sqlx::query_as::<_, ZoneVersion>(
            AssertSqlSafe(format!("{}{}", r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = $1 AND serial = $2
            "#, lock_clause(lock_level))),
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&mut **pg_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn prune_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let pg_tx = tx.as_postgres()?;

        // Each zone's newest version survives regardless of age: the IXFR
        // up-to-date response reads it.
        let result = sqlx::query(
            r#"
            DELETE FROM zone_versions h
            USING (
                SELECT zone_id AS newest_zone_id, MAX(serial) AS newest_serial
                FROM zone_versions
                GROUP BY zone_id
            ) newest
            WHERE newest.newest_zone_id = h.zone_id
              AND h.created_at < $1 AND h.serial < newest.newest_serial
            "#,
        )
        .bind(cutoff)
        .execute(&mut **pg_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
