use crate::database::{
    DatabasePool, model::record_history::RecordHistory, repository::RecordHistoryRepository,
};
use async_trait::async_trait;
use sqlx::Row;

pub struct PostgresRecordHistoryRepository {
    pool: DatabasePool,
}

impl PostgresRecordHistoryRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordHistoryRepository for PostgresRecordHistoryRepository {
    async fn create(&self, mut record_history: RecordHistory) -> Result<RecordHistory, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let result = sqlx::query(
            r#"
            INSERT INTO record_history (log, record_id)
            VALUES ($1, $2)
            RETURNING id
            "#,
        )
        .bind(&record_history.log)
        .bind(record_history.record_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        record_history.id = result.get("id");
        Ok(record_history)
    }

    async fn create_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        mut record_history: RecordHistory,
    ) -> Result<RecordHistory, String> {
        let result = sqlx::query(
            r#"
            INSERT INTO record_history (log, record_id)
            VALUES ($1, $2)
            RETURNING id
            "#,
        )
        .bind(&record_history.log)
        .bind(record_history.record_id)
        .fetch_one(tx.as_mut())
        .await
        .map_err(|e| e.to_string())?;

        record_history.id = result.get("id");
        Ok(record_history)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<RecordHistory>, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let record_history = sqlx::query_as::<_, RecordHistory>(
            "SELECT id, log, created_at, record_id FROM record_history WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record_history)
    }

    async fn get_by_record_id(&self, record_id: i32) -> Result<Vec<RecordHistory>, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let record_histories = sqlx::query_as::<_, RecordHistory>(
            "SELECT id, log, created_at, record_id FROM record_history WHERE record_id = $1 ORDER BY created_at DESC"
        )
        .bind(record_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record_histories)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM record_history WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
