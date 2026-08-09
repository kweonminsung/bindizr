use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    model::catalog_zone_state::CatalogZoneState,
    repository::{CatalogZoneStateRepository, RepositoryTx},
};

/// Sqlite-backed implementation of `CatalogZoneStateRepository`.
/// Every method runs on the caller's transaction, so no pool is held.
pub struct SqliteCatalogZoneStateRepository;

#[async_trait]
impl CatalogZoneStateRepository for SqliteCatalogZoneStateRepository {
    async fn update_serial_for_signature_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<CatalogZoneState, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // Advance the catalog serial only when the signature changes, kept
        // monotonic, so secondaries re-transfer the catalog zone only on real changes.
        sqlx::query(
            r#"
            INSERT INTO catalog_zone_state (name, signature, serial)
            VALUES (?, ?, ?)
            ON CONFLICT(name)
            DO UPDATE SET
                serial = CASE
                    WHEN signature = excluded.signature THEN serial
                    ELSE max(serial + 1, excluded.serial)
                END,
                signature = excluded.signature,
                updated_at = CURRENT_TIMESTAMP
            "#,
        )
        .bind(name)
        .bind(signature)
        .bind(base_serial)
        .execute(&mut **sqlite_tx)
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
        .fetch_one(&mut **sqlite_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
