use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    repository::{
        DnssecRecordFilter, DnssecRecordRepository, LockLevel, RepositoryTx,
        sql::{apex_owner_sql, lock_clause},
    },
};

/// MySQL-backed implementation of `DnssecRecordRepository`.
pub(crate) struct MySqlDnssecRecordRepository {
    pool: Pool<MySql>,
}

impl MySqlDnssecRecordRepository {
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DnssecRecordRepository for MySqlDnssecRecordRepository {
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        const CHUNK: usize = 500;
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
            query.execute(&mut **mysql_tx).await?;
        }
        Ok(())
    }

    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let records = sqlx::query_as::<_, DnssecRecord>(AssertSqlSafe(format!(
            "{}{}",
            r#"
            SELECT id, zone_id, name, record_type, covered_record_type, ttl, rdata, expires_at, rrset_digest
            FROM dnssec_records
            WHERE zone_id = ?
            ORDER BY id
            "#,
            lock_clause(lock_level)
        )))
        .bind(zone_id)
        .fetch_all(&mut **mysql_tx)
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

        let mysql_tx = tx.as_mysql()?;

        const CHUNK: usize = 2000;
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
            query.execute(&mut **mysql_tx).await?;
        }
        Ok(())
    }

    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query("DELETE FROM dnssec_records WHERE zone_id = ?")
            .bind(zone_id)
            .execute(&mut **mysql_tx)
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
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN CONCAT(z.name, '.') ELSE CONCAT(d.name, '.', z.name, '.') END) = LOWER(?)
              )
              AND (? IS NULL OR d.record_type = ?)
              AND (? IS NULL OR d.ttl = ?)
              AND (? IS NULL OR d.ttl >= ?)
              AND (? IS NULL OR d.ttl <= ?)
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
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
                    OR LOWER(CASE WHEN d.name = {apex_owner} THEN CONCAT(z.name, '.') ELSE CONCAT(d.name, '.', z.name, '.') END) = LOWER(?)
              )
              AND (? IS NULL OR d.record_type = ?)
              AND (? IS NULL OR d.ttl = ?)
              AND (? IS NULL OR d.ttl >= ?)
              AND (? IS NULL OR d.ttl <= ?)
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
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
