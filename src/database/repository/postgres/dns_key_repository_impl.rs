use crate::database::error::DatabaseError;
use crate::database::{model::dns_key::DnsKey, repository::DnsKeyRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresDnsKeyRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnsKeyRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsKeyRepository for PostgresDnsKeyRepository {
    async fn create(&self, mut dns_key: DnsKey) -> Result<DnsKey, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query_as::<_, (i32,)>(
            r#"
            INSERT INTO dns_keys (name, key_type, key_algorithm, key_name, secret)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(&dns_key.name)
        .bind(dns_key.key_type.as_str())
        .bind(dns_key.key_algorithm.as_str())
        .bind(&dns_key.key_name)
        .bind(&dns_key.secret)
        .fetch_one(&mut *conn)
        .await?;

        dns_key.id = result.0;

        Ok(dns_key)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<DnsKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_key = sqlx::query_as::<_, DnsKey>(
            "SELECT id, name, key_type, key_algorithm, key_name, secret, created_at FROM dns_keys WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns_key)
    }

    async fn get_by_key_name(&self, key_name: &str) -> Result<Option<DnsKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_key = sqlx::query_as::<_, DnsKey>(
            "SELECT id, name, key_type, key_algorithm, key_name, secret, created_at FROM dns_keys WHERE key_name = $1"
        )
        .bind(key_name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns_key)
    }

    async fn get_all(&self) -> Result<Vec<DnsKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_keys = sqlx::query_as::<_, DnsKey>(
            "SELECT id, name, key_type, key_algorithm, key_name, secret, created_at FROM dns_keys ORDER BY id"
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(dns_keys)
    }

    async fn update(&self, dns_key: DnsKey) -> Result<DnsKey, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE dns_keys 
            SET name = $1, key_type = $2, key_algorithm = $3, key_name = $4, secret = $5
            WHERE id = $6
            "#,
        )
        .bind(&dns_key.name)
        .bind(dns_key.key_type.as_str())
        .bind(dns_key.key_algorithm.as_str())
        .bind(&dns_key.key_name)
        .bind(&dns_key.secret)
        .bind(dns_key.id)
        .execute(&mut *conn)
        .await?;

        Ok(dns_key)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM dns_keys WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
