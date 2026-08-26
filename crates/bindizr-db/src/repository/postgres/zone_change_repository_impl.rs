use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::zone_change::ZoneChange,
    repository::{LockLevel, RepositoryTx, ZoneChangeRepository, sql::lock_clause},
};

/// PostgreSQL-backed implementation of `ZoneChangeRepository`.
pub(crate) struct PostgresZoneChangeRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneChangeRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for PostgresZoneChangeRepository {
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        const CHUNK: usize = 500;
        for chunk in changes.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO zone_journal (zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived) VALUES ",
            );
            let mut p = 1;
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!(
                    "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    p,
                    p + 1,
                    p + 2,
                    p + 3,
                    p + 4,
                    p + 5,
                    p + 6,
                    p + 7,
                    p + 8,
                    p + 9
                ));
                p += 10;
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
                .execute(&mut **postgres_tx)
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
    async fn list_between_serials_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        let pg_tx = tx.as_postgres()?;

        sqlx::query_as::<_, ZoneChange>(
            AssertSqlSafe(format!("{}{}", r#"
            SELECT zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived
            FROM zone_journal
            WHERE zone_id = $1 AND serial > $2 AND serial <= $3
            ORDER BY serial, id
            "#, lock_clause(lock_level)))
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&mut **pg_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn prune_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, DatabaseError> {
        let pg_tx = tx.as_postgres()?;

        // Delete whole serials only: everything up to the highest serial whose
        // newest row predates the cutoff, so remaining IXFR steps stay complete.
        let result = sqlx::query(
            r#"
            DELETE FROM zone_journal zc
            USING (
                SELECT zone_id AS cutoff_zone_id, MAX(serial) AS cutoff_serial
                FROM zone_journal
                WHERE created_at < $1
                GROUP BY zone_id
            ) boundaries
            WHERE boundaries.cutoff_zone_id = zc.zone_id AND zc.serial <= boundaries.cutoff_serial
            "#,
        )
        .bind(cutoff)
        .execute(&mut **pg_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
