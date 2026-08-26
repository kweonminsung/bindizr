use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    repository::{
        DnssecRecordFilter, DnssecRecordRepository, LockLevel, RepositoryTx,
        sql::{apex_owner_sql, lock_clause},
    },
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

    async fn list_tx(
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

    async fn list_by_filter_with_zone(
        &self,
        filter: DnssecRecordFilter,
    ) -> Result<Vec<DnssecRecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let apex_owner = apex_owner_sql();
        let records = sqlx::query_as::<_, DnssecRecordWithZone>(AssertSqlSafe(format!(
            r#"
            SELECT d.name, d.record_type, d.ttl, d.rdata, d.zone_id, z.name AS zone_name
            FROM dnssec_records d
            INNER JOIN zones z ON z.id = d.zone_id
            WHERE ($1::TEXT IS NULL OR d.zone_id = (SELECT id FROM zones WHERE name = $2))
              AND (
                    $3::TEXT IS NULL
                    OR LOWER(d.name) = LOWER($4)
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) = LOWER($5)
              )
              AND ($6::INT4 IS NULL OR d.record_type = $7)
              AND ($8::INT4 IS NULL OR d.ttl = $9)
              AND ($10::INT4 IS NULL OR d.ttl >= $11)
              AND ($12::INT4 IS NULL OR d.ttl <= $13)
              AND (
                    $14::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = $14 AND p.zone_id = d.zone_id)
              )
            -- d.name ties across an RRset, so without d.id a plan change
            -- between two pages could drop or repeat a row.
            ORDER BY d.name, d.id
            LIMIT $15 OFFSET $16
            "#
        )))
        .bind(&filter.zone_name)
        .bind(&filter.zone_name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(filter.record_type)
        .bind(filter.record_type)
        .bind(filter.ttl)
        .bind(filter.ttl)
        .bind(filter.min_ttl)
        .bind(filter.min_ttl)
        .bind(filter.max_ttl)
        .bind(filter.max_ttl)
        .bind(filter.scope_token_id)
        .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
        .bind(
            filter
                .offset
                .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
                .unwrap_or(0),
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    async fn count_by_filter(&self, filter: DnssecRecordFilter) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let apex_owner = apex_owner_sql();
        let count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
            r#"
            SELECT COUNT(*)
            FROM dnssec_records d
            INNER JOIN zones z ON z.id = d.zone_id
            WHERE ($1::TEXT IS NULL OR d.zone_id = (SELECT id FROM zones WHERE name = $2))
              AND (
                    $3::TEXT IS NULL
                    OR LOWER(d.name) = LOWER($4)
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) = LOWER($5)
              )
              AND ($6::INT4 IS NULL OR d.record_type = $7)
              AND ($8::INT4 IS NULL OR d.ttl = $9)
              AND ($10::INT4 IS NULL OR d.ttl >= $11)
              AND ($12::INT4 IS NULL OR d.ttl <= $13)
              AND (
                    $14::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = $14 AND p.zone_id = d.zone_id)
              )
            "#
        )))
        .bind(&filter.zone_name)
        .bind(&filter.zone_name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(filter.record_type)
        .bind(filter.record_type)
        .bind(filter.ttl)
        .bind(filter.ttl)
        .bind(filter.min_ttl)
        .bind(filter.min_ttl)
        .bind(filter.max_ttl)
        .bind(filter.max_ttl)
        .bind(filter.scope_token_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }
}
