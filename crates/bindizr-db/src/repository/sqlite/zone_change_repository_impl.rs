use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::zone_change::ZoneChange,
    repository::{RepositoryTx, ZoneChangeRepository},
};

/// SQLite-backed implementation of `ZoneChangeRepository`.
pub struct SqliteZoneChangeRepository {
    pool: Pool<Sqlite>,
}

impl SqliteZoneChangeRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for SqliteZoneChangeRepository {
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // 8 columns per row; keep bind count under SQLite's conservative limit.
        const CHUNK: usize = 100;
        const ROW: &str = "(?, ?, ?, ?, ?, ?, ?, ?)";
        for chunk in changes.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO zone_changes (zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority) VALUES ",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(ROW);
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
                .execute(&mut **sqlite_tx)
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
            WHERE zone_id = ? AND serial > ? AND serial <= ?
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

    async fn get_changes_between_serials_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            FROM zone_changes
            WHERE zone_id = ? AND serial > ? AND serial <= ?
            ORDER BY serial, id
            "#
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&mut **sqlite_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
