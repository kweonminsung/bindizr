use crate::database::error::DatabaseError;
use crate::database::{model::record_history::RecordHistory, repository::RecordHistoryRepository};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlRecordHistoryRepository {
    pool: Pool<MySql>,
}

impl MySqlRecordHistoryRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordHistoryRepository for MySqlRecordHistoryRepository {
    async fn create(
        &self,
        mut record_history: RecordHistory,
    ) -> Result<RecordHistory, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            "INSERT INTO record_history (log, record_name, record_type) VALUES (?, ?, ?)",
        )
        .bind(&record_history.log)
        .bind(&record_history.record_name)
        .bind(&record_history.record_type)
        .execute(&mut *conn)
        .await?;

        record_history.id = result.last_insert_id() as i32;

        Ok(record_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<RecordHistory>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record_history = sqlx::query_as::<_, RecordHistory>(
            "SELECT id, log, created_at, record_name, record_type FROM record_history WHERE id = ?",
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
            "SELECT id, log, created_at, record_name, record_type FROM record_history WHERE record_name = ? AND record_type = ? ORDER BY created_at DESC",
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

        sqlx::query("DELETE FROM record_history WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
