use crate::error::DatabaseError;
use crate::{model::catalog_zone_state::CatalogZoneState, repository::CatalogZoneStateRepository};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresCatalogZoneStateRepository {
    pool: Pool<Postgres>,
}

impl PostgresCatalogZoneStateRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CatalogZoneStateRepository for PostgresCatalogZoneStateRepository {
    async fn update_serial_for_signature(
        &self,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<CatalogZoneState, DatabaseError> {
        sqlx::query_as::<_, CatalogZoneState>(
            r#"
            INSERT INTO catalog_zone_state (name, signature, serial)
            VALUES ($1, $2, $3)
            ON CONFLICT (name)
            DO UPDATE SET
                serial = CASE
                    WHEN catalog_zone_state.signature = EXCLUDED.signature THEN catalog_zone_state.serial
                    ELSE GREATEST(catalog_zone_state.serial + 1, EXCLUDED.serial)
                END,
                signature = EXCLUDED.signature,
                updated_at = CURRENT_TIMESTAMP
            RETURNING name, signature, serial, updated_at
            "#,
        )
        .bind(name)
        .bind(signature)
        .bind(base_serial)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
