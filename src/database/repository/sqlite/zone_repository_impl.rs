use crate::database::{model::zone::Zone, repository::ZoneRepository};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

pub struct SqliteZoneRepository {
    pool: Pool<Sqlite>,
}

impl SqliteZoneRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for SqliteZoneRepository {
    async fn create(&self, mut zone: Zone) -> Result<Zone, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, primary_ns_ip, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.primary_ns_ip)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .execute(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        zone.id = result.last_insert_rowid() as i32;
        Ok(zone)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let zone = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let zone = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn get_all(&self) -> Result<Vec<Zone>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let zones = sqlx::query_as::<_, Zone>("SELECT * FROM zones ORDER BY name")
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
            SET name = ?, primary_ns = ?, primary_ns_ip = ?, admin_email = ?, 
                ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ?
            WHERE id = ?
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.primary_ns_ip)
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

        sqlx::query("DELETE FROM zones WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
