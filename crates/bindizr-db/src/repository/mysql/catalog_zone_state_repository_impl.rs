use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    repository::{CatalogZoneStateRepository, RepositoryTx},
};

/// Mysql-backed implementation of `CatalogZoneStateRepository`.
/// Every method runs on the caller's transaction, so no pool is held.
pub(crate) struct MySqlCatalogZoneStateRepository;

#[async_trait]
impl CatalogZoneStateRepository for MySqlCatalogZoneStateRepository {
    async fn update_serial_for_signature_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // Advance the catalog serial only when the signature changes, kept
        // monotonic, so secondaries re-transfer the catalog zone only on real changes.
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
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_scalar::<_, i32>(
            r#"
            SELECT serial
            FROM catalog_zone_state
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_one(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
