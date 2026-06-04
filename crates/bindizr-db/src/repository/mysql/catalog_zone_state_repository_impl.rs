use async_trait::async_trait;
use sqlx::{MySql, Pool};

use crate::{
    error::DatabaseError,
    model::catalog_zone_state::CatalogZoneState,
    repository::{CatalogZoneStateRepository, RepositoryTx, RepositoryTxKind},
};

pub struct MySqlCatalogZoneStateRepository {
    pool: Pool<MySql>,
}

impl MySqlCatalogZoneStateRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CatalogZoneStateRepository for MySqlCatalogZoneStateRepository {
    async fn update_serial_for_signature(
        &self,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<CatalogZoneState, DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO catalog_zone_state (name, signature, serial)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                serial = IF(signature = VALUES(signature), serial, GREATEST(serial + 1, VALUES(serial))),
                signature = VALUES(signature)
            "#,
        )
        .bind(name)
        .bind(signature)
        .bind(base_serial)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, CatalogZoneState>(
            r#"
            SELECT name, signature, serial, updated_at
            FROM catalog_zone_state
            WHERE name = ?
            FOR UPDATE
            "#,
        )
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn update_serial_for_signature_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<CatalogZoneState, DatabaseError> {
        let mysql_tx = match &mut tx.0 {
            RepositoryTxKind::MySQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected MySQL)".to_string(),
                ));
            }
        };

        sqlx::query(
            r#"
            INSERT INTO catalog_zone_state (name, signature, serial)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                serial = IF(signature = VALUES(signature), serial, GREATEST(serial + 1, VALUES(serial))),
                signature = VALUES(signature)
            "#,
        )
        .bind(name)
        .bind(signature)
        .bind(base_serial)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, CatalogZoneState>(
            r#"
            SELECT name, signature, serial, updated_at
            FROM catalog_zone_state
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_one(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
