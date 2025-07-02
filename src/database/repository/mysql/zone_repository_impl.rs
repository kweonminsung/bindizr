use crate::database::{DatabasePool, model::zone::Zone, repository::ZoneRepository};
use async_trait::async_trait;

pub struct MySqlZoneRepository {
    pool: DatabasePool,
}

impl MySqlZoneRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for MySqlZoneRepository {
    async fn create(&self, mut zone: Zone) -> Result<Zone, String> {
        let mut conn = self.pool.get_connection().await?;

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

        zone.id = result
            .last_insert_id()
            .map(|id| id as i32)
            .ok_or("Failed to retrieve last insert ID")?;

        Ok(zone)
    }

    async fn create_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        mut zone: Zone,
    ) -> Result<Zone, String> {
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
        .execute(tx.as_mut())
        .await
        .map_err(|e| e.to_string())?;

        zone.id = result
            .last_insert_id()
            .map(|id| id as i32)
            .ok_or("Failed to retrieve last insert ID")?;

        Ok(zone)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, String> {
        let mut conn = self.pool.get_connection().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, String> {
        let mut conn = self.pool.get_connection().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT * FROM zones WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn get_all(&self) -> Result<Vec<Zone>, String> {
        let mut conn = self.pool.get_connection().await?;

        let zones = sqlx::query_as::<_, Zone>("SELECT * FROM zones ORDER BY name")
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(zones)
    }

    async fn update(&self, zone: Zone) -> Result<Zone, String> {
        let mut conn = self.pool.get_connection().await?;

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

    async fn update_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        zone: Zone,
    ) -> Result<Zone, String> {
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
        .execute(tx.as_mut())
        .await
        .map_err(|e| e.to_string())?;

        Ok(zone)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self.pool.get_connection().await?;

        sqlx::query("DELETE FROM zones WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    async fn delete_with_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        id: i32,
    ) -> Result<(), String> {
        sqlx::query("DELETE FROM zones WHERE id = ?")
            .bind(id)
            .execute(tx.as_mut())
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
