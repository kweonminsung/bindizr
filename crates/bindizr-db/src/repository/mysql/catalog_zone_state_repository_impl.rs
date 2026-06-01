use crate::error::DatabaseError;
use crate::{model::catalog_zone_state::CatalogZoneState, repository::CatalogZoneStateRepository};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlCatalogZoneStateRepository {
    pool: Pool<MySql>,
}

impl MySqlCatalogZoneStateRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CatalogZoneStateRepository for MySqlCatalogZoneStateRepository {
    async fn update_serial_for_signature(
        &self,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<CatalogZoneState, DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO catalog_zone_state (name, signature, serial)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                serial = IF(signature = VALUES(signature), serial, GREATEST(serial + 1, VALUES(serial))),
                signature = VALUES(signature)
            "#,
        )
        .bind(name)
        .bind(signature)
        .bind(base_serial)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, CatalogZoneState>(
            r#"
            SELECT name, signature, serial, updated_at
            FROM catalog_zone_state
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
