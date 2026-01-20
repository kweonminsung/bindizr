use crate::database::error::DatabaseError;
use crate::database::{model::dns_instance::DnsInstance, repository::DnsInstanceRepository};
use async_trait::async_trait;
use sqlx::{Postgres, Pool};

pub struct PostgresDnsInstanceRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnsInstanceRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsInstanceRepository for PostgresDnsInstanceRepository {
    async fn create(&self, mut dns_instance: DnsInstance) -> Result<DnsInstance, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query_as::<_, (i32,)>(
            r#"
            INSERT INTO dns_instances (name, host, rndc_port, rndc_key_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(&dns_instance.name)
        .bind(&dns_instance.host)
        .bind(dns_instance.rndc_port)
        .bind(dns_instance.rndc_key_id)
        .fetch_one(&mut *conn)
        .await?;

        dns_instance.id = result.0;

        Ok(dns_instance)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<DnsInstance>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_instance = sqlx::query_as::<_, DnsInstance>(
            "SELECT id, name, host, rndc_port, rndc_key_id, created_at FROM dns_instances WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(dns_instance)
    }

    async fn get_all(&self) -> Result<Vec<DnsInstance>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let dns_instances = sqlx::query_as::<_, DnsInstance>(
            "SELECT id, name, host, rndc_port, rndc_key_id, created_at FROM dns_instances ORDER BY id"
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(dns_instances)
    }

    async fn update(&self, dns_instance: DnsInstance) -> Result<DnsInstance, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE dns_instances 
            SET name = $1, host = $2, rndc_port = $3, rndc_key_id = $4
            WHERE id = $5
            "#,
        )
        .bind(&dns_instance.name)
        .bind(&dns_instance.host)
        .bind(dns_instance.rndc_port)
        .bind(dns_instance.rndc_key_id)
        .bind(dns_instance.id)
        .execute(&mut *conn)
        .await?;

        Ok(dns_instance)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM dns_instances WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
