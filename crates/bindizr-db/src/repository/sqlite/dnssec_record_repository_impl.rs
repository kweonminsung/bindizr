use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    repository::{
        DnssecRecordFilter, DnssecRecordRepository, LockLevel, RepositoryTx, sql::apex_owner_sql,
    },
};

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

    async fn list_tx(
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

    async fn count_zone_ids(&self) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(DISTINCT zone_id) FROM dnssec_records")
                .fetch_one(&mut *conn)
                .await?;

        Ok(count as u64)
    }

    async fn list_zone_ids_expiring_within_refresh(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone_ids = sqlx::query_scalar::<_, i32>(
            r#"
            SELECT DISTINCT r.zone_id
            FROM dnssec_records r
            JOIN zones z ON z.id = r.zone_id
            JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
            WHERE r.expires_at IS NOT NULL
              AND datetime(r.expires_at) < datetime(?, '+' || p.signature_refresh_days || ' days')
            "#,
        )
        .bind(now)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zone_ids)
    }

    async fn count_expiring_within_refresh(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM dnssec_records r
            JOIN zones z ON z.id = r.zone_id
            JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
            WHERE r.expires_at IS NOT NULL
              AND datetime(r.expires_at) < datetime(?, '+' || p.signature_refresh_days || ' days')
            "#,
        )
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
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
            WHERE (? IS NULL OR d.zone_id = (SELECT id FROM zones WHERE name = ?))
              AND (
                    ? IS NULL
                    OR LOWER(d.name) = LOWER(?)
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) = LOWER(?)
              )
              AND (? IS NULL OR d.record_type = ?)
              AND (? IS NULL OR d.ttl = ?)
              AND (? IS NULL OR d.ttl >= ?)
              AND (? IS NULL OR d.ttl <= ?)
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM token_grants p
                               WHERE p.api_token_id = ? AND p.zone_id = d.zone_id)
              )
            -- d.name ties across an RRset, so without d.id a plan change
            -- between two pages could drop or repeat a row.
            ORDER BY d.name, d.id
            LIMIT ? OFFSET ?
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
            WHERE (? IS NULL OR d.zone_id = (SELECT id FROM zones WHERE name = ?))
              AND (
                    ? IS NULL
                    OR LOWER(d.name) = LOWER(?)
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN z.name || '.' ELSE d.name || '.' || z.name || '.' END) = LOWER(?)
              )
              AND (? IS NULL OR d.record_type = ?)
              AND (? IS NULL OR d.ttl = ?)
              AND (? IS NULL OR d.ttl >= ?)
              AND (? IS NULL OR d.ttl <= ?)
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM token_grants p
                               WHERE p.api_token_id = ? AND p.zone_id = d.zone_id)
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
        .bind(filter.scope_token_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }
}
