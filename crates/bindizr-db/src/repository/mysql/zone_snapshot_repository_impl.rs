use async_trait::async_trait;
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::zone_snapshot::ZoneSnapshot,
    repository::{LockLevel, RepositoryTx, ZoneSnapshotRepository, sql::lock_clause},
};

/// MySQL-backed implementation of `ZoneSnapshotRepository`.
pub(crate) struct MySqlZoneSnapshotRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneSnapshotRepository {
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneSnapshotRepository for MySqlZoneSnapshotRepository {
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query(
            r#"
            INSERT INTO zone_soa_history (zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                primary_ns = VALUES(primary_ns),
                admin_email = VALUES(admin_email),
                ttl = VALUES(ttl),
                refresh = VALUES(refresh),
                retry = VALUES(retry),
                expire = VALUES(expire),
                minimum_ttl = VALUES(minimum_ttl)
            "#,
        )
        .bind(snapshot.zone_id)
        .bind(snapshot.serial)
        .bind(&snapshot.primary_ns)
        .bind(&snapshot.admin_email)
        .bind(snapshot.ttl)
        .bind(snapshot.refresh)
        .bind(snapshot.retry)
        .bind(snapshot.expire)
        .bind(snapshot.minimum_ttl)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(snapshot.zone_id)
        .bind(snapshot.serial)
        .fetch_one(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_by_zone_id_and_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, DatabaseError> {
        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn list_by_zone_id_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneSnapshot>, DatabaseError> {
        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
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
    async fn list_by_zone_id(
        &self,
        zone_id: i32,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneSnapshot>, DatabaseError> {
        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ?
            ORDER BY serial DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(zone_id)
        .bind(limit as i64)
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn count_by_zone_id(&self, zone_id: i32) -> Result<u64, DatabaseError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM zone_soa_history WHERE zone_id = ?")
                .bind(zone_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        Ok(count as u64)
    }

    async fn get_by_zone_id_and_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneSnapshot>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query_as::<_, ZoneSnapshot>(
            AssertSqlSafe(format!("{}{}", r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ? AND serial = ?
            "#, lock_clause(lock_level))),
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
