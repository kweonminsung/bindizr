use crate::database::error::DatabaseError;
use crate::database::{model::zone_change::ZoneChange, repository::ZoneChangeRepository};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

pub struct SqliteZoneChangeRepository {
    pool: Pool<Sqlite>,
}

impl SqliteZoneChangeRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for SqliteZoneChangeRepository {
    async fn get_changes_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            FROM zone_changes
            WHERE zone_id = ? AND serial > ? AND serial <= ?
            ORDER BY serial, id
            "#
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
