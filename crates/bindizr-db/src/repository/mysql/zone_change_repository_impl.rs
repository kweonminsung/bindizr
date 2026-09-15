use async_trait::async_trait;
use chrono::Utc;
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::zone_change::ZoneChange,
    repository::{LockLevel, RepositoryTx, ZoneChangeRepository, sql::lock_clause},
};

pub(crate) struct MySqlZoneChangeRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneChangeRepository {
    /// Create a repository for journal entries using the supplied pool.
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for MySqlZoneChangeRepository {
    /// Insert a batch of journal entries in the current transaction.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        const CHUNK: usize = 500;
        const ROW: &str = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        for chunk in changes.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO zone_journal (zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived, created_at) VALUES ",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(ROW);
            }

            let now = Utc::now();
            let mut query = sqlx::query(AssertSqlSafe(sql));
            for c in chunk {
                query = query
                    .bind(c.zone_id)
                    .bind(c.serial)
                    .bind(c.operation)
                    .bind(&c.record_name)
                    .bind(c.record_type.clone())
                    .bind(c.record_value.clone())
                    .bind(c.record_rdata.clone())
                    .bind(c.record_ttl)
                    .bind(c.record_priority)
                    .bind(c.derived)
                    .bind(now);
            }
            query
                .execute(&mut **mysql_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// List journal entries in the interval `(from_serial, to_serial]`.
    async fn list_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived
            FROM zone_journal
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

    /// Count journal entries in the interval `(from_serial, to_serial]`.
    async fn count_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<u64, DatabaseError> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM zone_journal
            WHERE zone_id = ? AND serial > ? AND serial <= ?
            "#,
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(count as u64)
    }

    /// List journal entries in the interval `(from_serial, to_serial]` in the current
    /// transaction.
    async fn list_between_serials_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query_as::<_, ZoneChange>(
            AssertSqlSafe(format!("{}{}", r#"
            SELECT zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived
            FROM zone_journal
            WHERE zone_id = ? AND serial > ? AND serial <= ?
            ORDER BY serial, id
            "#, lock_clause(lock_level)))
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    /// Prune one zone's journal rows older than `cutoff` in the current transaction.
    async fn prune_by_zone_id_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // Delete whole serials only: everything up to the highest serial with
        // a row older than the cutoff, so remaining IXFR steps stay complete.
        // MySQL reads a DELETE's own table only through a derived table.
        let result = sqlx::query(
            r#"
            DELETE FROM zone_journal
            WHERE zone_id = ?
              AND serial <= (
                  SELECT cutoff_serial FROM (
                      SELECT MAX(serial) AS cutoff_serial FROM zone_journal
                      WHERE zone_id = ? AND created_at < ?
                  ) boundary
              )
            "#,
        )
        .bind(zone_id)
        .bind(zone_id)
        .bind(cutoff)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
