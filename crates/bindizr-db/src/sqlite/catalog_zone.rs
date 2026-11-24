use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{Sqlite, Transaction};

use crate::error::DatabaseError;

/// Ensure the catalog row exists under SQLite's writer reservation.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Sqlite>,
    catalog_zone_name: &ZoneName,
) -> Result<(), DatabaseError> {
    sqlx::query(
        r#"
        INSERT INTO catalog_zones (name, digest, serial)
        VALUES (?, '', 0)
        ON CONFLICT (name) DO NOTHING
        "#,
    )
    .bind(catalog_zone_name)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Store the digest and return the resulting serial on the reserved row.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Sqlite>,
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
