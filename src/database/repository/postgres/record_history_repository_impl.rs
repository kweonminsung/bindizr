use crate::database::error::DatabaseError;
use crate::database::{model::record_history::RecordHistory, repository::RecordHistoryRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

pub struct PostgresRecordHistoryRepository {
    pool: Pool<Postgres>,
}

impl PostgresRecordHistoryRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordHistoryRepository for PostgresRecordHistoryRepository {
    async fn create(
        &self,
        mut record_history: RecordHistory,
    ) -> Result<RecordHistory, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            "INSERT INTO record_history (log, record_name, record_type) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(&record_history.log)
        .bind(&record_history.record_name)
        .bind(&record_history.record_type)
        .fetch_one(&mut *conn)
        .await?;

        record_history.id = result.get::<i32, _>(0);

        Ok(record_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<RecordHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record_history = sqlx::query_as::<_, RecordHistory>(
            "SELECT id, log, created_at, record_name, record_type FROM record_history WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(record_history)
    }

    async fn get_by_record_name_and_type(
        &self,
        record_name: &str,
        record_type: &str,
    ) -> Result<Vec<RecordHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record_histories = sqlx::query_as::<_, RecordHistory>(
            "SELECT id, log, created_at, record_name, record_type FROM record_history WHERE record_name = $1 AND record_type = $2 ORDER BY created_at DESC",
        )
        .bind(record_name)
        .bind(record_type)
        .fetch_all(&mut *conn)
        .await
        ?;

        Ok(record_histories)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM record_history WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
