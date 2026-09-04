use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::zone_version::ZoneVersion,
    repository::{LockLevel, RepositoryTx, ZoneVersionRepository},
};

/// Hides serials whose journal carries only signer-generated changes
/// (re-signs, rollovers). Serials with user changes, serials with no journal
/// at all (zone creation, forced bumps), and the current serial stay listed.
///
/// Takes one extra `?` bind of the zone id, keeping the current-serial
/// subquery uncorrelated.
const USER_CHANGES_FILTER: &str = r#"
              AND (
                  zone_versions.serial = (SELECT zones.serial FROM zones WHERE zones.id = ?)
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

pub(crate) struct SqliteZoneVersionRepository {
    pool: Pool<Sqlite>,
}

impl SqliteZoneVersionRepository {
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneVersionRepository for SqliteZoneVersionRepository {
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query(
            r#"
            INSERT INTO zone_versions (zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(zone_id, serial)
            DO UPDATE SET
                mname = excluded.mname,
                rname = excluded.rname,
                default_ttl = excluded.default_ttl,
                refresh = excluded.refresh,
                retry = excluded.retry,
                expire = excluded.expire,
                minimum_ttl = excluded.minimum_ttl
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
        .execute(&mut **sqlite_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, ZoneVersion>(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(version.zone_id)
        .bind(version.serial)
        .fetch_one(&mut **sqlite_tx)
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
            WHERE zone_id = ? AND serial = ?
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
            WHERE zone_id = ? AND serial >= ? AND serial <= ?
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
        let mut query = sqlx::query_as::<_, ZoneVersion>(AssertSqlSafe(format!(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = ?{filter}
            ORDER BY serial DESC
            LIMIT ? OFFSET ?
            "#
        )))
        .bind(zone_id);
        if user_changes_only {
            query = query.bind(zone_id);
        }
        query
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
        let mut query = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM zone_versions WHERE zone_id = ?{filter}"
        )))
        .bind(zone_id);
        if user_changes_only {
            query = query.bind(zone_id);
        }
        let count: i64 = query
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
        _lock_level: LockLevel,
    ) -> Result<Option<ZoneVersion>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query_as::<_, ZoneVersion>(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_versions
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&mut **sqlite_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn prune_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // Each zone's newest version survives regardless of age: the IXFR
        // up-to-date response reads it. datetime(?) normalizes the bound value
        // to the column's stored format.
        let result = sqlx::query(
            r#"
            DELETE FROM zone_versions
            WHERE created_at < datetime(?)
              AND serial < (
                  SELECT MAX(newest.serial) FROM zone_versions newest
                  WHERE newest.zone_id = zone_versions.zone_id
              )
            "#,
        )
        .bind(cutoff)
        .execute(&mut **sqlite_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
