use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{MySql, Transaction};

use crate::error::DatabaseError;

/// Lock the catalog row, creating it if missing. The duplicate-key update
/// takes an exclusive lock even when it does not change the existing row.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, MySql>,
    catalog_zone_name: &ZoneName,
) -> Result<(), DatabaseError> {
    sqlx::query(
        r#"
        INSERT INTO catalog_zones (name, digest, serial)
        VALUES (?, '', 0)
        ON DUPLICATE KEY UPDATE serial = serial
        "#,
    )
    .bind(catalog_zone_name)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Store the digest and return the resulting serial on the locked row.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, MySql>,
    catalog_zone_name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    // Advance the catalog serial only when the digest changes, so secondaries
    // re-transfer on real changes; past the maximum it wraps to one (RFC 2136, Section 7.11).
    sqlx::query(
        r#"
        UPDATE catalog_zones
        SET serial = CASE
                WHEN digest = '' THEN ?
                WHEN digest = ? THEN serial
                WHEN serial = 4294967295 THEN 1
                ELSE serial + 1
            END,
            digest = ?
        WHERE name = ?
        "#,
    )
    .bind(base_serial)
    .bind(digest)
    .bind(digest)
    .bind(catalog_zone_name)
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
