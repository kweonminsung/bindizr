use crate::database::error::DatabaseError;
use crate::database::{model::zone_dns_config::ZoneDnsConfig, repository::ZoneDnsConfigRepository};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlZoneDnsConfigRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneDnsConfigRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneDnsConfigRepository for MySqlZoneDnsConfigRepository {
    async fn create(
        &self,
        mut zone_dns_config: ZoneDnsConfig,
    ) -> Result<ZoneDnsConfig, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zone_dns_config (zone_id, dns_instance_id, dns_key_id)
            VALUES (?, ?, ?)
            "#,
        )
        .bind(zone_dns_config.zone_id)
        .bind(zone_dns_config.dns_instance_id)
        .bind(zone_dns_config.dns_key_id)
        .execute(&mut *conn)
        .await?;

        zone_dns_config.id = result.last_insert_id() as i32;

        Ok(zone_dns_config)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ZoneDnsConfig>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_dns_config = sqlx::query_as::<_, ZoneDnsConfig>(
            "SELECT id, zone_id, dns_instance_id, dns_key_id, created_at FROM zone_dns_config WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(zone_dns_config)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<ZoneDnsConfig>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_dns_configs = sqlx::query_as::<_, ZoneDnsConfig>(
            "SELECT id, zone_id, dns_instance_id, dns_key_id, created_at FROM zone_dns_config WHERE zone_id = ? ORDER BY id"
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
            "SELECT id, zone_id, dns_instance_id, dns_key_id, created_at FROM zone_dns_config WHERE dns_instance_id = ? ORDER BY id"
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
            SET zone_id = ?, dns_instance_id = ?, dns_key_id = ?
            WHERE id = ?
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

        sqlx::query("DELETE FROM zone_dns_config WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
