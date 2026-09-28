use sqlx::{Sqlite, Transaction};

use crate::error::DatabaseError;

/// Mark a zone for DNSSEC withdrawal in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
) -> Result<(), DatabaseError> {
    sqlx::query("INSERT INTO dnssec_withdrawals (zone_id) VALUES (?)")
        .bind(zone_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

    Ok(())
}

/// Read a zone's DNSSEC withdrawal marker in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
) -> Result<Option<i32>, DatabaseError> {
    sqlx::query_scalar::<_, i32>("SELECT zone_id FROM dnssec_withdrawals WHERE zone_id = ?")
        .bind(zone_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
}

/// Clear a zone's DNSSEC withdrawal marker in the current transaction.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: i32,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM dnssec_withdrawals WHERE zone_id = ?")
        .bind(zone_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

    Ok(())
}
