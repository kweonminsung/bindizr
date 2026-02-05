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
            INSERT INTO zone_history (log, zone_name)
            VALUES ($1, $2)
            RETURNING id
            "#,
        )
        .bind(&zone_history.log)
        .bind(&zone_history.zone_name)
        .fetch_one(&mut *conn)
        .await?;

        zone_history.id = result.get("id");
        Ok(zone_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_history = sqlx::query_as::<_, ZoneHistory>(
            "SELECT id, log, created_at, zone_name FROM zone_history WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(zone_history)
    }

    async fn get_by_zone_name(&self, zone_name: &str) -> Result<Vec<ZoneHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_histories = sqlx::query_as::<_, ZoneHistory>(
            "SELECT id, log, created_at, zone_name FROM zone_history WHERE zone_name = $1 ORDER BY created_at DESC"
        )
        .bind(zone_name)
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
