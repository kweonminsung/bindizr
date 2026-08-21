use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::dnssec_record::DnssecRecord,
    repository::{DnssecRecordRepository, LockLevel, RepositoryTx, sql::lock_clause},
};

/// PostgreSQL-backed implementation of `DnssecRecordRepository`.
pub(crate) struct PostgresDnssecRecordRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnssecRecordRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecRecordRepository for PostgresDnssecRecordRepository {
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        const CHUNK: usize = 500;
        for chunk in records.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO dnssec_records (zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest) VALUES ",
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
            query.execute(&mut **postgres_tx).await?;
        }
        Ok(())
    }

    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<DnssecRecord>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records = sqlx::query_as::<_, DnssecRecord>(
            r#"
            SELECT id, zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest
            FROM dnssec_records
            WHERE zone_id = $1
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
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let records = sqlx::query_as::<_, DnssecRecord>(AssertSqlSafe(format!(
            "{}{}",
            r#"
            SELECT id, zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest
            FROM dnssec_records
            WHERE zone_id = $1
            ORDER BY id
            "#,
            lock_clause(lock_level)
        )))
        .bind(zone_id)
        .fetch_all(&mut **postgres_tx)
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

        let postgres_tx = tx.as_postgres()?;

        sqlx::query("DELETE FROM dnssec_records WHERE id = ANY($1)")
            .bind(ids)
            .execute(&mut **postgres_tx)
            .await?;
        Ok(())
    }

    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("DELETE FROM dnssec_records WHERE zone_id = $1")
            .bind(zone_id)
            .execute(&mut **postgres_tx)
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
            WHERE expires_at IS NOT NULL AND expires_at < $1
            "#,
        )
        .bind(cutoff)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_ids)
    }
}
