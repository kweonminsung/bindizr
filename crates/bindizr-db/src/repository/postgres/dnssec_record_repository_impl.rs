use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres};

use crate::{
    error::DatabaseError,
    model::dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    repository::{
        DnssecRecordFilter, DnssecRecordRepository, LockLevel, RepositoryTx,
        sql::{
            apex_owner_sql, concat_pipes, grant_record_match_sql, lock_clause, name_like_pattern,
            refresh_bound,
        },
    },
};

pub(crate) struct PostgresDnssecRecordRepository {
    pool: Pool<Postgres>,
}

impl PostgresDnssecRecordRepository {
    /// Create a repository for derived DNSSEC records using the supplied pool.
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecRecordRepository for PostgresDnssecRecordRepository {
    /// Insert a batch of derived DNSSEC records in the current transaction.
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

    /// List derived DNSSEC records for a zone in the current transaction.
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

    /// Delete the derived DNSSEC records with the supplied IDs in the current transaction.
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

    /// Delete all derived DNSSEC records for a zone in the current transaction.
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

    /// Count zones with stored derived DNSSEC records.
    async fn count_zone_ids(&self) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(DISTINCT zone_id) FROM dnssec_records")
                .fetch_one(&mut *conn)
                .await?;

        Ok(count as u64)
    }

    /// List zones with signatures due for renewal.
    async fn list_zone_ids_expiring_within_refresh(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        // The per-policy threshold is no constant, so nothing can seek the
        // index; this widest-window bound is, and the comparison below refines it.
        let Some(max_refresh_days) = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(signature_refresh_days) FROM dnssec_policies",
        )
        .fetch_one(&mut *conn)
        .await?
        else {
            return Ok(Vec::new());
        };
        let bound = refresh_bound(cutoff, max_refresh_days);

        let zone_ids = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT DISTINCT r.zone_id
            FROM dnssec_records r
            JOIN zones z ON z.id = r.zone_id
            JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
            WHERE r.expires_at IS NOT NULL
              AND r.expires_at < $1
              AND r.expires_at < $2 + make_interval(days => p.signature_refresh_days)
            "#,
        )
        .bind(bound)
        .bind(cutoff)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_ids)
    }

    /// Count signatures due for renewal.
    async fn count_expiring_within_refresh(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        // The per-policy threshold is no constant, so nothing can seek the
        // index; this widest-window bound is, and the comparison below refines it.
        let Some(max_refresh_days) = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(signature_refresh_days) FROM dnssec_policies",
        )
        .fetch_one(&mut *conn)
        .await?
        else {
            return Ok(0);
        };
        let bound = refresh_bound(cutoff, max_refresh_days);

        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM dnssec_records r
            JOIN zones z ON z.id = r.zone_id
            JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
            WHERE r.expires_at IS NOT NULL
              AND r.expires_at < $1
              AND r.expires_at < $2 + make_interval(days => p.signature_refresh_days)
            "#,
        )
        .bind(bound)
        .bind(cutoff)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }

    /// Count signatures that have already expired.
    async fn count_expired(&self, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM dnssec_records
            WHERE expires_at IS NOT NULL
              AND expires_at <= $1
            "#,
        )
        .bind(cutoff)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }

    /// List matching derived DNSSEC records with their zone metadata.
    async fn list_by_filter_with_zone(
        &self,
        filter: DnssecRecordFilter,
    ) -> Result<Vec<DnssecRecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let apex_owner = apex_owner_sql();
        let search = name_like_pattern(filter.search.as_deref());
        let grant_match = grant_record_match_sql("d", None, concat_pipes);
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
                    $14::TEXT IS NULL
                    OR LOWER(z.name) LIKE LOWER($15) ESCAPE '\'
                    OR LOWER(d.name) LIKE LOWER($16) ESCAPE '\'
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) LIKE LOWER($17) ESCAPE '\'
              )
              AND (
                    $18::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM token_grants p
                               WHERE p.api_token_id = $18 AND p.zone_id = d.zone_id
                                 AND {grant_match})
              )
            -- every type at one name shares d.name, so without d.id a plan change
            -- between two pages could drop or repeat a row.
            ORDER BY d.name, d.id
            LIMIT $19 OFFSET $20
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
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
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

    /// Count derived DNSSEC records matching the filter.
    async fn count_by_filter(&self, filter: DnssecRecordFilter) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let apex_owner = apex_owner_sql();
        let search = name_like_pattern(filter.search.as_deref());
        let grant_match = grant_record_match_sql("d", None, concat_pipes);
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
                    $14::TEXT IS NULL
                    OR LOWER(z.name) LIKE LOWER($15) ESCAPE '\'
                    OR LOWER(d.name) LIKE LOWER($16) ESCAPE '\'
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) LIKE LOWER($17) ESCAPE '\'
              )
              AND (
                    $18::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM token_grants p
                               WHERE p.api_token_id = $18 AND p.zone_id = d.zone_id
                                 AND {grant_match})
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
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(filter.scope_token_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }
}
