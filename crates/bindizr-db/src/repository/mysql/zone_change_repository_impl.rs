use async_trait::async_trait;
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::zone_change::ZoneChange,
    repository::{LockLevel, RepositoryTx, ZoneChangeRepository, sql::lock_clause},
};

/// MySQL-backed implementation of `ZoneChangeRepository`.
pub(crate) struct MySqlZoneChangeRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneChangeRepository {
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for MySqlZoneChangeRepository {
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        const CHUNK: usize = 500;
        const ROW: &str = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        for chunk in changes.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO zone_journal (zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived) VALUES ",
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
                    .bind(c.operation)
                    .bind(&c.record_name)
                    .bind(c.record_type.clone())
                    .bind(c.record_value.clone())
                    .bind(c.record_rdata.clone())
                    .bind(c.record_ttl)
                    .bind(c.record_priority)
                    .bind(c.derived);
            }
            query
                .execute(&mut **mysql_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
        }
        Ok(())
    }

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

    async fn prune_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // Delete whole serials only: everything up to the highest serial whose
        // newest row predates the cutoff, so remaining IXFR steps stay complete.
        let result = sqlx::query(
            r#"
            DELETE zc FROM zone_journal zc
            JOIN (
                SELECT zone_id AS cutoff_zone_id, MAX(serial) AS cutoff_serial
                FROM zone_journal
                WHERE created_at < ?
                GROUP BY zone_id
            ) boundaries
              ON boundaries.cutoff_zone_id = zc.zone_id AND zc.serial <= boundaries.cutoff_serial
            "#,
        )
        .bind(cutoff)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
