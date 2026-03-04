use crate::database::error::DatabaseError;
use crate::database::{model::dns_server::DnsServer, repository::DnsServerRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresDnsServerRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnsServerRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsServerRepository for PostgresDnsServerRepository {
    async fn get_all(&self) -> Result<Vec<DnsServer>, DatabaseError> {
        sqlx::query_as::<_, DnsServer>(
            r#"
            SELECT id, ip_address, port, created_at
            FROM dns_servers
            ORDER BY id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<DnsServer>, DatabaseError> {
        sqlx::query_as::<_, DnsServer>(
            r#"
            SELECT id, ip_address, port, created_at
            FROM dns_servers
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn create(&self, dns_server: DnsServer) -> Result<DnsServer, DatabaseError> {
        sqlx::query_as::<_, DnsServer>(
            r#"
            INSERT INTO dns_servers (ip_address, port)
            VALUES ($1, $2)
            RETURNING id, ip_address, port, created_at
            "#,
        )
        .bind(&dns_server.ip_address)
        .bind(dns_server.port)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn update(&self, dns_server: DnsServer) -> Result<DnsServer, DatabaseError> {
        sqlx::query_as::<_, DnsServer>(
            r#"
            UPDATE dns_servers
            SET ip_address = $1, port = $2
            WHERE id = $3
            RETURNING id, ip_address, port, created_at
            "#,
        )
        .bind(&dns_server.ip_address)
        .bind(dns_server.port)
        .bind(dns_server.id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            DELETE FROM dns_servers WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(())
    }
}
