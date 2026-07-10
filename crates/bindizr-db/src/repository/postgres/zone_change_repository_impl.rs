use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::zone_change::ZoneChange,
    repository::{RepositoryTx, RepositoryTxKind, ZoneChangeRepository},
};

/// PostgreSQL-backed implementation of `ZoneChangeRepository`.
pub struct PostgresZoneChangeRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneChangeRepository {
    /// Create a new repository backed by the given connection pool.
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

    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        const CHUNK: usize = 500;
        for chunk in changes.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO zone_changes (zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority) VALUES ",
            );
            let mut p = 1;
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!(
                    "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    p,
                    p + 1,
                    p + 2,
                    p + 3,
                    p + 4,
                    p + 5,
                    p + 6,
                    p + 7
                ));
                p += 8;
            }

            let mut query = sqlx::query(AssertSqlSafe(sql));
            for c in chunk {
                query = query
                    .bind(c.zone_id)
                    .bind(c.serial)
                    .bind(c.operation.clone())
                    .bind(c.record_name.clone())
                    .bind(c.record_type.clone())
                    .bind(c.record_value.clone())
                    .bind(c.record_ttl)
                    .bind(c.record_priority);
            }
            query
                .execute(&mut **postgres_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        }
        Ok(())
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
