use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;
use sqlx::{Postgres, Transaction};

use crate::error::DatabaseError;

/// Lock the catalog row, creating it if missing. The conflict update locks
/// the existing row in the same statement.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Postgres>,
    catalog_zone_name: &ZoneName,
) -> Result<(), DatabaseError> {
    sqlx::query(
        r#"
        INSERT INTO catalog_zones (name, digest, serial)
        VALUES ($1, '', 0)
        ON CONFLICT (name) DO UPDATE SET serial = catalog_zones.serial
        "#,
    )
    .bind(catalog_zone_name)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Store the digest and return the resulting serial on the locked row.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Postgres>,
    catalog_zone_name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    // Advance the catalog serial only when the digest changes, so secondaries
    // re-transfer on real changes; past the maximum it wraps to one (RFC 2136, Section 7.11).
    let serial = sqlx::query_scalar::<_, Serial>(
        r#"
        UPDATE catalog_zones
        SET serial = CASE
                WHEN digest = '' THEN $3
                WHEN digest = $2 THEN serial
                WHEN serial = 4294967295 THEN 1
                ELSE serial + 1
            END,
            digest = $2
        WHERE name = $1
        RETURNING serial
        "#,
    )
    .bind(catalog_zone_name)
    .bind(digest)
    .bind(base_serial)
    .fetch_one(&mut **tx)
    .await?;

    Ok(serial)
}
