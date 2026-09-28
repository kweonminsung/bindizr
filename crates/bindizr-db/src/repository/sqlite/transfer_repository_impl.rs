use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::transfer::{Transfer, TransferWithZone},
    repository::TransferRepository,
};

pub(crate) struct SqliteTransferRepository {
    pool: Pool<Sqlite>,
}

impl SqliteTransferRepository {
    /// Create a repository for transfers using the supplied pool.
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TransferRepository for SqliteTransferRepository {
    /// Insert the transfer, or replace the row for its client address and zone.
    async fn upsert(&self, transfer: Transfer) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            INSERT INTO transfers (client_addr, zone_id, kind, result, incremental, serial, served_at, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(client_addr, zone_id)
            DO UPDATE SET
                kind = excluded.kind,
                result = excluded.result,
                incremental = excluded.incremental,
                serial = excluded.serial,
                served_at = excluded.served_at,
                error = excluded.error
            "#,
        )
        .bind(&transfer.client_addr)
        .bind(transfer.zone_id)
        .bind(transfer.kind.as_str())
        .bind(transfer.result.as_str())
        .bind(transfer.incremental)
        .bind(transfer.serial)
        .bind(transfer.served_at)
        .bind(&transfer.error)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// The transfers served to a client address, newest first, with zone names.
    async fn list_by_client_addr_with_zone(
        &self,
        client_addr: &str,
    ) -> Result<Vec<TransferWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let transfers = sqlx::query_as::<_, TransferWithZone>(
            r#"
            SELECT t.client_addr, t.kind, t.result, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
            FROM transfers t
            INNER JOIN zones z ON z.id = t.zone_id
            WHERE t.client_addr = ?
            ORDER BY t.served_at DESC
            "#,
        )
        .bind(client_addr)
        .fetch_all(&mut *conn)
        .await?;

        Ok(transfers)
    }

    /// The transfer of one zone served to a client address.
    async fn get_by_client_addr_and_zone_name_with_zone(
        &self,
        client_addr: &str,
        zone_name: &str,
    ) -> Result<Option<TransferWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let transfer = sqlx::query_as::<_, TransferWithZone>(
            r#"
            SELECT t.client_addr, t.kind, t.result, t.incremental, t.serial, t.served_at, t.error, z.name AS zone_name
            FROM transfers t
            INNER JOIN zones z ON z.id = t.zone_id
            WHERE t.client_addr = ? AND z.name = ?
            "#,
        )
        .bind(client_addr)
        .bind(zone_name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(transfer)
    }
}
