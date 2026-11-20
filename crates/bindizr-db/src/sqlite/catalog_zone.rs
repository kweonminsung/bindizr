use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{Sqlite, Transaction};

use crate::LockLevel;
use crate::error::DatabaseError;

/// Find the catalog's stored serial; the transaction's writer reservation
/// stands in for the row lock.
pub(crate) async fn find_serial_tx(
    tx: &mut Transaction<'_, Sqlite>,
    catalog_zone_name: &ZoneName,
    _lock_level: LockLevel,
) -> Result<Option<Serial>, DatabaseError> {
    let serial = sqlx::query_scalar::<_, Serial>("SELECT serial FROM catalog_zones WHERE name = ?")
        .bind(catalog_zone_name)
        .fetch_optional(&mut **tx)
        .await?;

    Ok(serial)
}

/// Upsert the catalog digest, advancing the serial only when `digest` changed;
/// return the serial in effect after the upsert.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Sqlite>,
    catalog_zone_name: &ZoneName,
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
    .bind(catalog_zone_name)
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
    .bind(catalog_zone_name)
    .fetch_one(&mut **tx)
    .await?;

    Ok(serial)
}
