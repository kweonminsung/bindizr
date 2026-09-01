use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    repository::{DnssecWithdrawalRepository, RepositoryTx},
};

/// Sqlite-backed implementation of `DnssecWithdrawalRepository`.
/// Every method runs on the caller's transaction, so no pool is held.
pub(crate) struct SqliteDnssecWithdrawalRepository;

#[async_trait]
impl DnssecWithdrawalRepository for SqliteDnssecWithdrawalRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let tx = tx.as_sqlite()?;

        sqlx::query("INSERT INTO dnssec_withdrawals (zone_id) VALUES (?)")
            .bind(zone_id)
            .execute(&mut **tx)
            .await
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(())
    }

    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<i32>, DatabaseError> {
        let tx = tx.as_sqlite()?;

        sqlx::query_scalar::<_, i32>("SELECT zone_id FROM dnssec_withdrawals WHERE zone_id = ?")
            .bind(zone_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn delete_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let tx = tx.as_sqlite()?;

        sqlx::query("DELETE FROM dnssec_withdrawals WHERE zone_id = ?")
            .bind(zone_id)
            .execute(&mut **tx)
            .await
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(())
    }
}
