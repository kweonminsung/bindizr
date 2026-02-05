use crate::database::error::DatabaseError;
use crate::database::{model::zone_dns_config::ZoneDnsConfig, repository::ZoneDnsConfigRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresZoneDnsConfigRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneDnsConfigRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneDnsConfigRepository for PostgresZoneDnsConfigRepository {
    async fn create(
        &self,
        mut zone_dns_config: ZoneDnsConfig,
    ) -> Result<ZoneDnsConfig, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query_as::<_, (i32,)>(
            r#"
            INSERT INTO zone_dns_config (zone_id, dns_instance_id, dns_key_id)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(zone_dns_config.zone_id)
        .bind(zone_dns_config.dns_instance_id)
        .bind(zone_dns_config.dns_key_id)
        .fetch_one(&mut *conn)
        .await?;

        zone_dns_config.id = result.0;

        Ok(zone_dns_config)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneDnsConfig>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_dns_config = sqlx::query_as::<_, ZoneDnsConfig>(
            "SELECT id, zone_id, dns_instance_id, dns_key_id, created_at FROM zone_dns_config WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(zone_dns_config)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneDnsConfig>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_dns_configs = sqlx::query_as::<_, ZoneDnsConfig>(
            "SELECT id, zone_id, dns_instance_id, dns_key_id, created_at FROM zone_dns_config WHERE zone_id = $1 ORDER BY id"
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_dns_configs)
    }

    async fn get_by_dns_instance_id(
        &self,
        dns_instance_id: i32,
    ) -> Result<Vec<ZoneDnsConfig>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_dns_configs = sqlx::query_as::<_, ZoneDnsConfig>(
            "SELECT id, zone_id, dns_instance_id, dns_key_id, created_at FROM zone_dns_config WHERE dns_instance_id = $1 ORDER BY id"
        )
        .bind(dns_instance_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_dns_configs)
    }

    async fn update(&self, zone_dns_config: ZoneDnsConfig) -> Result<ZoneDnsConfig, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE zone_dns_config 
            SET zone_id = $1, dns_instance_id = $2, dns_key_id = $3
            WHERE id = $4
            "#,
        )
        .bind(zone_dns_config.zone_id)
        .bind(zone_dns_config.dns_instance_id)
        .bind(zone_dns_config.dns_key_id)
        .bind(zone_dns_config.id)
        .execute(&mut *conn)
        .await?;

        Ok(zone_dns_config)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zone_dns_config WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
