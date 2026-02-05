use crate::database::error::DatabaseError;
use crate::database::{model::dns_key::DnsKey, repository::DnsKeyRepository};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

pub struct SqliteDnsKeyRepository {
    pool: Pool<Sqlite>,
}

impl SqliteDnsKeyRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsKeyRepository for SqliteDnsKeyRepository {
    async fn create(&self, mut dns_key: DnsKey) -> Result<DnsKey, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO dns_keys (dns_id, key_id)
            VALUES (?, ?)
            "#,
        )
        .bind(dns_key.dns_id)
        .bind(dns_key.key_id)
        .execute(&mut *conn)
        .await?;

        dns_key.id = result.last_insert_rowid() as i32;

        Ok(dns_key)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<DnsKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_key = sqlx::query_as::<_, DnsKey>(
            "SELECT id, dns_id, key_id, created_at FROM dns_keys WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns_key)
    }

    async fn get_by_dns_id(&self, dns_id: i32) -> Result<Vec<DnsKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_keys = sqlx::query_as::<_, DnsKey>(
            "SELECT id, dns_id, key_id, created_at FROM dns_keys WHERE dns_id = ? ORDER BY id",
        )
        .bind(dns_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(dns_keys)
    }

    async fn update(&self, dns_key: DnsKey) -> Result<DnsKey, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE dns_keys 
            SET dns_id = ?, key_id = ?
            WHERE id = ?
            "#,
        )
        .bind(dns_key.dns_id)
        .bind(dns_key.key_id)
        .bind(dns_key.id)
        .execute(&mut *conn)
        .await?;

        Ok(dns_key)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM dns_keys WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
