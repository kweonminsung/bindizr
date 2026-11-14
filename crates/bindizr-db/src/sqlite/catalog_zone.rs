use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{Sqlite, Transaction};

use crate::error::DatabaseError;

/// Upsert the catalog digest, advancing the serial only when `digest` changed;
/// return the serial in effect after the upsert.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Sqlite>,
    name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    // Advance the catalog serial only when the digest changes, so secondaries
    // re-transfer on real changes; past the maximum it wraps to one (RFC 2136, Section 7.11).
    sqlx::query(
        r#"
        INSERT INTO catalog_zones (name, digest, serial)
        VALUES (?, ?, ?)
        ON CONFLICT(name)
        DO UPDATE SET
            serial = CASE
                WHEN digest = excluded.digest THEN serial
                WHEN serial = 4294967295 THEN 1
                ELSE serial + 1
            END,
            digest = excluded.digest
        "#,
    )
    .bind(name)
    .bind(digest)
    .bind(base_serial)
    .execute(&mut **tx)
    .await?;

    let serial = sqlx::query_scalar::<_, Serial>(
        r#"
        SELECT serial
        FROM catalog_zones
        WHERE name = ?
        "#,
    )
    .bind(name)
    .fetch_one(&mut **tx)
    .await?;

    Ok(serial)
}
