use crate::database::{
    model::record::{Record, RecordType},
    repository::RecordRepository,
};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

pub struct PostgresRecordRepository {
    pool: Pool<Postgres>,
}

impl PostgresRecordRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordRepository for PostgresRecordRepository {
    async fn create(&self, mut record: Record) -> Result<Record, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_str())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        record.id = result.get("id");
        Ok(record)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let record = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 ORDER BY name"
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
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let record = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE name = $1 AND record_type = $2"
        )
        .bind(name)
        .bind(record_type.to_str())
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(record)
    }

    async fn get_records_by_name(&self, name: &str) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE name = $1"
        )
        .bind(name)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(records)
    }

    async fn get_all(&self) -> Result<Vec<Record>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records ORDER BY name"
        )
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
            SET name = $1, record_type = $2, value = $3, ttl = $4, priority = $5, zone_id = $6
            WHERE id = $7
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

        sqlx::query("DELETE FROM records WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
