use bindizr_core::dns::Serial;
use sqlx::{MySql, Transaction};

use crate::error::DatabaseError;

/// Store a catalog digest and advance its serial when the digest changes in the current
/// transaction.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, MySql>,
    name: &str,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
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
    .execute(&mut **tx)
    .await?;

    sqlx::query_scalar::<_, Serial>(
        r#"
        SELECT serial
        FROM catalog_zones
        WHERE name = ?
        "#,
    )
    .bind(name)
    .fetch_one(&mut **tx)
    .await
    .map_err(DatabaseError::from)
}
