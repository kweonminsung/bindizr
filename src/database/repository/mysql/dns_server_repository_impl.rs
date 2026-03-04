use crate::database::error::DatabaseError;
use crate::database::{model::dns_server::DnsServer, repository::DnsServerRepository};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlDnsServerRepository {
    pool: Pool<MySql>,
}

impl MySqlDnsServerRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnsServerRepository for MySqlDnsServerRepository {
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
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn create(&self, dns_server: DnsServer) -> Result<DnsServer, DatabaseError> {
        let result = sqlx::query(
            r#"
            INSERT INTO dns_servers (ip_address, port)
            VALUES (?, ?)
            "#,
        )
        .bind(&dns_server.ip_address)
        .bind(dns_server.port)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        let id = result.last_insert_id() as i32;

        sqlx::query_as::<_, DnsServer>(
            r#"
            SELECT id, ip_address, port, created_at
            FROM dns_servers
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn update(&self, dns_server: DnsServer) -> Result<DnsServer, DatabaseError> {
        sqlx::query(
            r#"
            UPDATE dns_servers
            SET ip_address = ?, port = ?
            WHERE id = ?
            "#,
        )
        .bind(&dns_server.ip_address)
        .bind(dns_server.port)
        .bind(dns_server.id)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, DnsServer>(
            r#"
            SELECT id, ip_address, port, created_at
            FROM dns_servers
            WHERE id = ?
            "#,
        )
        .bind(dns_server.id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            DELETE FROM dns_servers WHERE id = ?
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(())
    }
}
