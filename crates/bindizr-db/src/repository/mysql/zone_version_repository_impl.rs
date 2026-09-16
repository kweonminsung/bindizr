use async_trait::async_trait;
use chrono::Utc;
use sqlx::{AssertSqlSafe, MySql, Pool};

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

pub(crate) struct MySqlZoneVersionRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneVersionRepository {
    /// Create a repository for zone versions using the supplied pool.
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneVersionRepository for MySqlZoneVersionRepository {
    /// Insert or update a zone version in the current transaction.
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query(
            r#"
            INSERT INTO zone_versions (zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                mname = VALUES(mname),
                rname = VALUES(rname),
                default_ttl = VALUES(default_ttl),
                refresh = VALUES(refresh),
                retry = VALUES(retry),
                expire = VALUES(expire),
                minimum_ttl = VALUES(minimum_ttl),
                change_source = VALUES(change_source),
                changed_by = VALUES(changed_by)
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
        .bind(version.change_source.as_str())
        .bind(&version.changed_by)
        .bind(Utc::now())
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        self.get_by_serial_tx(tx, version.zone_id, version.serial, LockLevel::None)
            .await?
            .ok_or_else(|| {
                DatabaseError::QueryFailed("upserted zone version did not read back".to_string())
            })
    }

    /// Find a zone version by zone ID and serial.
    async fn get_by_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, DatabaseError> {
        sqlx::query_as::<_, ZoneVersion>(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
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

    /// List zone versions in the closed interval `[from_serial, to_serial]`.
    async fn list_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, DatabaseError> {
        sqlx::query_as::<_, ZoneVersion>(
            r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
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

    /// List zone versions for a zone.
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
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
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

    /// Count zone versions using the requested change filter.
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

    /// Find a zone version by zone ID and serial in the current transaction.
    async fn get_by_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneVersion>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query_as::<_, ZoneVersion>(
            AssertSqlSafe(format!("{}{}", r#"
            SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
            FROM zone_versions
            WHERE zone_id = ? AND serial = ?
            "#, lock_level.clause())),
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    /// Prune one zone's old versions, keeping its newest, in the current transaction.
    async fn prune_by_zone_id_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // The zone's newest version survives regardless of age: the IXFR
        // up-to-date response reads it. MySQL reads a DELETE's own table only
        // through a derived table.
        let result = sqlx::query(
            r#"
            DELETE FROM zone_versions
            WHERE zone_id = ? AND created_at < ?
              AND serial < (
                  SELECT newest_serial FROM (
                      SELECT MAX(serial) AS newest_serial FROM zone_versions WHERE zone_id = ?
                  ) newest
              )
            "#,
        )
        .bind(zone_id)
        .bind(cutoff)
        .bind(zone_id)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
