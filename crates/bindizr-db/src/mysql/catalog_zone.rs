use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{MySql, Transaction};

use crate::error::DatabaseError;

/// Find the catalog's stored serial, locking its row for update.
pub(crate) async fn find_serial_tx(
    tx: &mut Transaction<'_, MySql>,
    catalog_zone_name: &ZoneName,
) -> Result<Option<Serial>, DatabaseError> {
    let serial = sqlx::query_scalar::<_, Serial>(
        "SELECT serial FROM catalog_zones WHERE name = ? FOR UPDATE",
    )
    .bind(catalog_zone_name)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(serial)
}

/// Upsert the catalog digest, advancing the serial only when `digest` changed;
/// return the serial in effect after the upsert.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, MySql>,
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
        ON DUPLICATE KEY UPDATE
            serial = IF(digest = VALUES(digest), serial, IF(serial = 4294967295, 1, serial + 1)),
            digest = VALUES(digest)
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
