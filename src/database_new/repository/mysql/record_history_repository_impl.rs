use crate::database_new::{
    DatabasePool, model::record_history::RecordHistory, repository::RecordHistoryRepository,
};
use async_trait::async_trait;

pub struct MySqlRecordHistoryRepository {
    pool: DatabasePool,
}

impl MySqlRecordHistoryRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordHistoryRepository for MySqlRecordHistoryRepository {
    async fn create(&self, mut record_history: RecordHistory) -> Result<RecordHistory, String> {
        let mut conn = self.pool.get_connection().await?;

        let result = sqlx::query("INSERT INTO record_history (log, record_id) VALUES (?, ?)")
            .bind(&record_history.log)
            .bind(record_history.record_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        record_history.id = result
            .last_insert_id()
            .map(|id| id as i32)
            .ok_or("Failed to retrieve last insert ID")?;
        Ok(record_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<RecordHistory>, String> {
        let mut conn = self.pool.get_connection().await?;

        let record_history =
            sqlx::query_as::<_, RecordHistory>("SELECT * FROM record_history WHERE id = ?")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| e.to_string())?;

        Ok(record_history)
    }

    async fn get_by_record_id(&self, record_id: i32) -> Result<Vec<RecordHistory>, String> {
        let mut conn = self.pool.get_connection().await?;

        let record_histories = sqlx::query_as::<_, RecordHistory>(
            "SELECT * FROM record_history WHERE record_id = ? ORDER BY created_at DESC",
        )
        .bind(record_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record_histories)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self.pool.get_connection().await?;

        sqlx::query("DELETE FROM record_history WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
