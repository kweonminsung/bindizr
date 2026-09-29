use bindizr_core::model::zone::ZoneId;
use sqlx::{Postgres, Transaction};

use crate::error::DatabaseError;

/// Mark a zone for DNSSEC withdrawal in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
) -> Result<(), DatabaseError> {
    sqlx::query("INSERT INTO dnssec_withdrawals (zone_id) VALUES ($1)")
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Read a zone's DNSSEC withdrawal marker in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
) -> Result<Option<ZoneId>, DatabaseError> {
    sqlx::query_scalar::<_, ZoneId>("SELECT zone_id FROM dnssec_withdrawals WHERE zone_id = $1")
        .bind(zone_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(DatabaseError::from)
}

/// Clear a zone's DNSSEC withdrawal marker in the current transaction.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM dnssec_withdrawals WHERE zone_id = $1")
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}
