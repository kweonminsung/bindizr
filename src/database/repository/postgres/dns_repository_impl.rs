use crate::database::error::DatabaseError;
use crate::database::{model::dns::Dns, repository::DnsRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresDnsRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnsRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsRepository for PostgresDnsRepository {
    async fn create(&self, mut dns: Dns) -> Result<Dns, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query_as::<_, (i32,)>(
            r#"
            INSERT INTO dnss (name, host, rndc_port)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(&dns.name)
        .bind(&dns.host)
        .bind(dns.rndc_port)
        .fetch_one(&mut *conn)
        .await?;

        dns.id = result.0;

        Ok(dns)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Dns>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns = sqlx::query_as::<_, Dns>(
            "SELECT id, name, host, rndc_port, created_at FROM dnss WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Dns>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns = sqlx::query_as::<_, Dns>(
            "SELECT id, name, host, rndc_port, created_at FROM dnss WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns)
    }

    async fn get_by_host(&self, host: &str) -> Result<Option<Dns>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns = sqlx::query_as::<_, Dns>(
            "SELECT id, name, host, rndc_port, created_at FROM dnss WHERE host = $1",
        )
        .bind(host)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns)
    }

    async fn get_all(&self) -> Result<Vec<Dns>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dnss = sqlx::query_as::<_, Dns>(
            "SELECT id, name, host, rndc_port, created_at FROM dnss ORDER BY id",
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(dnss)
    }

    async fn update(&self, dns: Dns) -> Result<Dns, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE dnss 
            SET name = $1, host = $2, rndc_port = $3
            WHERE id = $4
            "#,
        )
        .bind(&dns.name)
        .bind(&dns.host)
        .bind(dns.rndc_port)
        .bind(dns.id)
        .execute(&mut *conn)
        .await?;

        Ok(dns)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM dnss WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
