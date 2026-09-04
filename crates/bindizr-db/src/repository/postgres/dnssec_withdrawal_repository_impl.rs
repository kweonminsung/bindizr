use async_trait::async_trait;

use crate::{
    error::DatabaseError,
    repository::{DnssecWithdrawalRepository, RepositoryTx},
};

/// Every method runs on the caller's transaction, so no pool is held.
pub(crate) struct PostgresDnssecWithdrawalRepository;

#[async_trait]
impl DnssecWithdrawalRepository for PostgresDnssecWithdrawalRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let tx = tx.as_postgres()?;

        sqlx::query("INSERT INTO dnssec_withdrawals (zone_id) VALUES ($1)")
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
        let tx = tx.as_postgres()?;

        sqlx::query_scalar::<_, i32>("SELECT zone_id FROM dnssec_withdrawals WHERE zone_id = $1")
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
        let tx = tx.as_postgres()?;

        sqlx::query("DELETE FROM dnssec_withdrawals WHERE zone_id = $1")
            .bind(zone_id)
            .execute(&mut **tx)
            .await
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(())
    }
}
