use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::dnssec_record::DnssecRecord,
    repository::{DnssecRecordRepository, LockLevel, RepositoryTx},
};

/// SQLite-backed implementation of `DnssecRecordRepository`.
pub(crate) struct SqliteDnssecRecordRepository {
    pool: Pool<Sqlite>,
}

impl SqliteDnssecRecordRepository {
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecRecordRepository for SqliteDnssecRecordRepository {
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // 8 columns per row; keep bind count under SQLite's conservative limit.
        const CHUNK: usize = 100;
        const ROW: &str = "(?, ?, ?, ?, ?, ?, ?, ?)";
        for chunk in records.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO dnssec_records (zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest) VALUES ",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(ROW);
            }

            let mut query = sqlx::query(AssertSqlSafe(sql));
            for r in chunk {
                query = query
                    .bind(r.zone_id)
                    .bind(&r.name)
                    .bind(r.record_type)
                    .bind(r.covered_record_type)
                    .bind(r.ttl)
                    .bind(r.rdata.clone())
                    .bind(r.expires_at)
                    .bind(r.rrset_digest.clone());
            }
            query.execute(&mut **sqlite_tx).await?;
        }
        Ok(())
    }

    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<DnssecRecord>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records = sqlx::query_as::<_, DnssecRecord>(
            r#"
            SELECT id, zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest
            FROM dnssec_records
            WHERE zone_id = ?
            ORDER BY id
            "#,
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    async fn list_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        _lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let records = sqlx::query_as::<_, DnssecRecord>(
            r#"
            SELECT id, zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest
            FROM dnssec_records
            WHERE zone_id = ?
            ORDER BY id
            "#,
        )
        .bind(zone_id)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(records)
    }

    async fn delete_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), DatabaseError> {
        if ids.is_empty() {
            return Ok(());
        }

        let sqlite_tx = tx.as_sqlite()?;

        // One bind per id; keep the count under SQLite's conservative limit.
        const CHUNK: usize = 900;
        for chunk in ids.chunks(CHUNK) {
            let mut sql = String::from("DELETE FROM dnssec_records WHERE id IN (");
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 { "?" } else { ",?" });
            }
            sql.push(')');

            let mut query = sqlx::query(AssertSqlSafe(sql));
            for id in chunk {
                query = query.bind(id);
            }
            query.execute(&mut **sqlite_tx).await?;
        }
        Ok(())
    }

    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("DELETE FROM dnssec_records WHERE zone_id = ?")
            .bind(zone_id)
            .execute(&mut **sqlite_tx)
            .await?;

        Ok(())
    }

    async fn list_zone_ids_expiring_before(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_ids = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT DISTINCT zone_id
            FROM dnssec_records
            WHERE expires_at IS NOT NULL AND expires_at < ?
            "#,
        )
        .bind(cutoff)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_ids)
    }
}
