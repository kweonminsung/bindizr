use crate::database::{
    DatabasePool,
    model::record::{Record, RecordType},
    repository::RecordRepository,
};
use async_trait::async_trait;

pub struct MySqlRecordRepository {
    pool: DatabasePool,
}

impl MySqlRecordRepository {
    pub fn new(pool: DatabasePool) -> Self {
        MySqlRecordRepository { pool }
    }
}

#[async_trait]
impl RecordRepository for MySqlRecordRepository {
    async fn create(&self, mut record: Record) -> Result<Record, String> {
        let mut conn = self.pool.get_connection().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        record.id = result
            .last_insert_id()
            .map(|id| id as i32)
            .ok_or("Failed to retrieve last insert ID")?;

        Ok(record)
    }

    async fn create_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        mut record: Record,
    ) -> Result<Record, String> {
        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(tx.as_mut())
        .await
        .map_err(|e| e.to_string())?;

        record.id = result
            .last_insert_id()
            .map(|id| id as i32)
            .ok_or("Failed to retrieve last insert ID")?;

        Ok(record)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, String> {
        let mut conn = self.pool.get_connection().await?;

        let record = sqlx::query_as::<_, Record>("SELECT * FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.get_connection().await?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT * FROM records WHERE zone_id = ? ORDER BY created_at DESC",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(records)
    }

    async fn get_by_name_and_type(
        &self,
        name: &str,
        record_type: &RecordType,
    ) -> Result<Option<Record>, String> {
        let mut conn = self.pool.get_connection().await?;

        let record =
            sqlx::query_as::<_, Record>("SELECT * FROM records WHERE name = ? AND record_type = ?")
                .bind(name)
                .bind(record_type.to_string())
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn get_all(&self) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.get_connection().await?;

        let records = sqlx::query_as::<_, Record>("SELECT * FROM records ORDER BY created_at DESC")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(records)
    }

    async fn update(&self, record: Record) -> Result<Record, String> {
        let mut conn = self.pool.get_connection().await?;

        sqlx::query(
            r#"
            UPDATE records
            SET name = ?, record_type = ?, content = ?, ttl = ?
            WHERE id = ?
        "#,
        )
        .bind(&record.name)
        .bind(&record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.id)
        .execute(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn update_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        record: Record,
    ) -> Result<Record, String> {
        sqlx::query(
            r#"
            UPDATE records
            SET name = ?, record_type = ?, value = ?, ttl = ?
            WHERE id = ?
        "#,
        )
        .bind(&record.name)
        .bind(&record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.id)
        .execute(tx.as_mut())
        .await
        .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self.pool.get_connection().await?;
        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn delete_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        id: i32,
    ) -> Result<(), String> {
        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(tx.as_mut())
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
