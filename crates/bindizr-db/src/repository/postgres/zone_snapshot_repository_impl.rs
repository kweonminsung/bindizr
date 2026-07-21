use async_trait::async_trait;
use sqlx::{Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::zone_snapshot::ZoneSnapshot,
    repository::{RepositoryTx, RepositoryTxKind, ZoneSnapshotRepository},
};

/// PostgreSQL-backed implementation of `ZoneSnapshotRepository`.
pub struct PostgresZoneSnapshotRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneSnapshotRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneSnapshotRepository for PostgresZoneSnapshotRepository {
    async fn upsert(&self, snapshot: ZoneSnapshot) -> Result<ZoneSnapshot, DatabaseError> {
        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            INSERT INTO zone_soa_history (zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (zone_id, serial)
            DO UPDATE SET
                primary_ns = EXCLUDED.primary_ns,
                admin_email = EXCLUDED.admin_email,
                ttl = EXCLUDED.ttl,
                refresh = EXCLUDED.refresh,
                retry = EXCLUDED.retry,
                expire = EXCLUDED.expire,
                minimum_ttl = EXCLUDED.minimum_ttl
            RETURNING id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
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
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            INSERT INTO zone_soa_history (zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (zone_id, serial)
            DO UPDATE SET
                primary_ns = EXCLUDED.primary_ns,
                admin_email = EXCLUDED.admin_email,
                ttl = EXCLUDED.ttl,
                refresh = EXCLUDED.refresh,
                retry = EXCLUDED.retry,
                expire = EXCLUDED.expire,
                minimum_ttl = EXCLUDED.minimum_ttl
            RETURNING id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
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
        .fetch_one(&mut **postgres_tx)
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
            WHERE zone_id = $1 AND serial = $2
            "#,
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_by_zone_id_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneSnapshot>, DatabaseError> {
        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
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
            WHERE zone_id = $1
            ORDER BY serial DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(zone_id)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn count_by_zone_id(&self, zone_id: i32) -> Result<u64, DatabaseError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM zone_soa_history WHERE zone_id = $1")
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
    ) -> Result<Option<ZoneSnapshot>, DatabaseError> {
        let pg_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = $1 AND serial = $2
            "#,
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&mut **pg_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
