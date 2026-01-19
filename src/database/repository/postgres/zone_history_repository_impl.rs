use crate::database::error::DatabaseError;
use crate::database::{model::zone_history::ZoneHistory, repository::ZoneHistoryRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

pub struct PostgresZoneHistoryRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneHistoryRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneHistoryRepository for PostgresZoneHistoryRepository {
    async fn create(&self, mut zone_history: ZoneHistory) -> Result<ZoneHistory, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zone_history (log, zone_id)
            VALUES ($1, $2)
            RETURNING id
            "#,
        )
        .bind(&zone_history.log)
        .bind(zone_history.zone_id)
        .fetch_one(&mut *conn)
        .await?;

        zone_history.id = result.get("id");
        Ok(zone_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_history = sqlx::query_as::<_, ZoneHistory>(
            "SELECT id, log, created_at, zone_id FROM zone_history WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(zone_history)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_histories = sqlx::query_as::<_, ZoneHistory>(
            "SELECT id, log, created_at, zone_id FROM zone_history WHERE zone_id = $1 ORDER BY created_at DESC"
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await
        ?;

        Ok(zone_histories)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zone_history WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
