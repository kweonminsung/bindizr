use crate::database::error::DatabaseError;
use crate::database::{
    model::zone_change::ZoneChange,
    repository::{RepositoryTx, RepositoryTxKind, ZoneChangeRepository},
};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

pub struct PostgresZoneChangeRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneChangeRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for PostgresZoneChangeRepository {
    async fn create(&self, zone_change: ZoneChange) -> Result<ZoneChange, DatabaseError> {
        sqlx::query_as::<_, ZoneChange>(
            r#"
            INSERT INTO zone_changes (zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            "#
        )
        .bind(zone_change.zone_id)
        .bind(zone_change.serial)
        .bind(&zone_change.operation)
        .bind(&zone_change.record_name)
        .bind(&zone_change.record_type)
        .bind(&zone_change.record_value)
        .bind(zone_change.record_ttl)
        .bind(zone_change.record_priority)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_change: ZoneChange,
    ) -> Result<ZoneChange, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query_as::<_, ZoneChange>(
            r#"
            INSERT INTO zone_changes (zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            "#,
        )
        .bind(zone_change.zone_id)
        .bind(zone_change.serial)
        .bind(&zone_change.operation)
        .bind(&zone_change.record_name)
        .bind(&zone_change.record_type)
        .bind(&zone_change.record_value)
        .bind(zone_change.record_ttl)
        .bind(zone_change.record_priority)
        .fetch_one(&mut **postgres_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_changes_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            FROM zone_changes
            WHERE zone_id = $1 AND serial > $2 AND serial <= $3
            ORDER BY serial, id
            "#
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
