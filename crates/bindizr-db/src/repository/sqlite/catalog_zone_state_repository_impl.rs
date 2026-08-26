use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    repository::{CatalogZoneStateRepository, RepositoryTx},
};

/// Sqlite-backed implementation of `CatalogZoneStateRepository`.
/// Every method runs on the caller's transaction, so no pool is held.
pub(crate) struct SqliteCatalogZoneStateRepository;

#[async_trait]
impl CatalogZoneStateRepository for SqliteCatalogZoneStateRepository {
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // Advance the catalog serial only when the digest changes, kept
        // monotonic, so secondaries re-transfer the catalog zone only on real changes.
        sqlx::query(
            r#"
            INSERT INTO catalog_zone_state (name, digest, serial)
            VALUES (?, ?, ?)
            ON CONFLICT(name)
            DO UPDATE SET
                serial = CASE
                    WHEN digest = excluded.digest THEN serial
                    ELSE max(serial + 1, excluded.serial)
                END,
                digest = excluded.digest
            "#,
        )
        .bind(name)
        .bind(digest)
        .bind(base_serial)
        .execute(&mut **sqlite_tx)
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
        .fetch_one(&mut **sqlite_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
