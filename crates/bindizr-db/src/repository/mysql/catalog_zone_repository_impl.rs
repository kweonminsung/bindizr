use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    repository::{CatalogZoneRepository, RepositoryTx},
};

/// Every method runs on the caller's transaction, so no pool is held.
pub(crate) struct MySqlCatalogZoneRepository;

#[async_trait]
impl CatalogZoneRepository for MySqlCatalogZoneRepository {
    /// Store a catalog digest and advance its serial when the digest changes in the current
    /// transaction.
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // Advance the catalog serial only when the digest changes, kept
        // monotonic, so secondaries re-transfer the catalog zone only on real changes.
        sqlx::query(
            r#"
            INSERT INTO catalog_zones (name, digest, serial)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                serial = IF(digest = VALUES(digest), serial, GREATEST(serial + 1, VALUES(serial))),
                digest = VALUES(digest)
            "#,
        )
        .bind(name)
        .bind(digest)
        .bind(base_serial)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_scalar::<_, i32>(
            r#"
            SELECT serial
            FROM catalog_zones
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_one(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
