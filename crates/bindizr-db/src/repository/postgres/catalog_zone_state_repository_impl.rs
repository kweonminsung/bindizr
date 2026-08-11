use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    repository::{CatalogZoneStateRepository, RepositoryTx},
};

/// Postgres-backed implementation of `CatalogZoneStateRepository`.
/// Every method runs on the caller's transaction, so no pool is held.
pub(crate) struct PostgresCatalogZoneStateRepository;

#[async_trait]
impl CatalogZoneStateRepository for PostgresCatalogZoneStateRepository {
    async fn update_serial_for_signature_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        // Advance the catalog serial only when the signature changes, kept
        // monotonic, so secondaries re-transfer the catalog zone only on real changes.
        sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO catalog_zone_state (name, signature, serial)
            VALUES ($1, $2, $3)
            ON CONFLICT (name)
            DO UPDATE SET
                serial = CASE
                    WHEN catalog_zone_state.signature = EXCLUDED.signature THEN catalog_zone_state.serial
                    ELSE GREATEST(catalog_zone_state.serial + 1, EXCLUDED.serial)
                END,
                signature = EXCLUDED.signature
            RETURNING serial
            "#,
        )
        .bind(name)
        .bind(signature)
        .bind(base_serial)
        .fetch_one(&mut **postgres_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
