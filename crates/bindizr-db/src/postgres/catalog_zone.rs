use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{Postgres, Transaction};

use crate::error::DatabaseError;

/// Store a catalog digest and advance its serial when the digest changes in the current
/// transaction.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Postgres>,
    name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    // Advance the catalog serial only when the digest changes, so secondaries
    // re-transfer on real changes; past the maximum it wraps to one (RFC 2136, Section 7.11).
    sqlx::query_scalar::<_, Serial>(
        r#"
        INSERT INTO catalog_zones (name, digest, serial)
        VALUES ($1, $2, $3)
        ON CONFLICT (name)
        DO UPDATE SET
            serial = CASE
                WHEN catalog_zones.digest = EXCLUDED.digest THEN catalog_zones.serial
                WHEN catalog_zones.serial = 4294967295 THEN 1
                ELSE catalog_zones.serial + 1
            END,
            digest = EXCLUDED.digest
        RETURNING serial
        "#,
    )
    .bind(name)
    .bind(digest)
    .bind(base_serial)
    .fetch_one(&mut **tx)
    .await
    .map_err(DatabaseError::from)
}
