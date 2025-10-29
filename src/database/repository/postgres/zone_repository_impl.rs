use crate::database::{model::zone::Zone, repository::ZoneRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

pub struct PostgresZoneRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for PostgresZoneRepository {
    async fn create(&self, mut zone: Zone) -> Result<Zone, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, primary_ns_ip, primary_ns_ipv6, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.primary_ns_ip)
        .bind(&zone.primary_ns_ipv6)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        zone.id = result.get("id");
        Ok(zone)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let zone = sqlx::query_as::<_, Zone>(
            "SELECT id, name, primary_ns, primary_ns_ip, primary_ns_ipv6, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let zone = sqlx::query_as::<_, Zone>(
            "SELECT id, name, primary_ns, primary_ns_ip, primary_ns_ipv6, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE name = $1"
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn get_all(&self) -> Result<Vec<Zone>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let zones = sqlx::query_as::<_, Zone>(
            "SELECT id, name, primary_ns, primary_ns_ip, primary_ns_ipv6, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones ORDER BY name"
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(zones)
    }

    async fn update(&self, zone: Zone) -> Result<Zone, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = $1, primary_ns = $2, primary_ns_ip = $3, primary_ns_ipv6 = $4, admin_email = $5,
                ttl = $6, serial = $7, refresh = $8, retry = $9, expire = $10, minimum_ttl = $11
            WHERE id = $11
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.primary_ns_ip)
        .bind(&zone.primary_ns_ipv6)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .bind(zone.id)
        .execute(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM zones WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
