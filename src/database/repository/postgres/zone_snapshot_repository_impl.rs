use crate::database::error::DatabaseError;
use crate::database::{model::zone_snapshot::ZoneSnapshot, repository::ZoneSnapshotRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresZoneSnapshotRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneSnapshotRepository {
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

    async fn get_by_zone_and_serial(
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
}
