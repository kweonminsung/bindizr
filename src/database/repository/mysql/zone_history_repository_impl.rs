use crate::database::error::DatabaseError;
use crate::database::{model::zone_history::ZoneHistory, repository::ZoneHistoryRepository};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlZoneHistoryRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneHistoryRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneHistoryRepository for MySqlZoneHistoryRepository {
    async fn create(&self, mut zone_history: ZoneHistory) -> Result<ZoneHistory, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query("INSERT INTO zone_history (log, zone_id) VALUES (?, ?)")
            .bind(&zone_history.log)
            .bind(zone_history.zone_id)
            .execute(&mut *conn)
            .await?;

        zone_history.id = result.last_insert_id() as i32;

        Ok(zone_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_history = sqlx::query_as::<_, ZoneHistory>(
            "SELECT id, log, created_at, zone_id FROM zone_history WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(zone_history)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_histories = sqlx::query_as::<_, ZoneHistory>(
            "SELECT id, log, created_at, zone_id FROM zone_history WHERE zone_id = ? ORDER BY created_at DESC",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await
        ?;

        Ok(zone_histories)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zone_history WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
