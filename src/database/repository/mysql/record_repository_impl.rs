use crate::database::{
    model::record::{Record, RecordType},
    repository::RecordRepository,
};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlRecordRepository {
    pool: Pool<MySql>,
}

impl MySqlRecordRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        MySqlRecordRepository { pool }
    }
}

#[async_trait]
impl RecordRepository for MySqlRecordRepository {
    async fn create(&self, mut record: Record) -> Result<Record, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

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

        record.id = result.last_insert_id() as i32;

        Ok(record)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let records =
            sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name")
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
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let record =
            sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE name = ? AND record_type = ?")
                .bind(name)
                .bind(record_type.to_string())
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn get_all(&self) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let records = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records ORDER BY name")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(records)
    }

    async fn update(&self, record: Record) -> Result<Record, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query(
            r#"
            UPDATE records
            SET name = ?, record_type = ?, value = ?, ttl = ?, priority = ?, zone_id = ?
            WHERE id = ?
        "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_str())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .bind(record.id)
        .execute(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;
        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
