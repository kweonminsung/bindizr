use async_trait::async_trait;
use bindizr_core::dns::name::OwnerName;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::record::{Record, RecordWithZone},
    repository::{
        LockLevel, RecordFilter, RecordRepository, RepositoryTx,
        sql::{
            apex_owner_sql, like_pattern, lock_clause, name_like_types_sql, normalize_partial_value,
        },
    },
};

/// PostgreSQL-backed implementation of `RecordRepository`.
pub(crate) struct PostgresRecordRepository {
    pool: Pool<Postgres>,
}

impl PostgresRecordRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        PostgresRecordRepository { pool }
    }
}

#[async_trait]
impl RecordRepository for PostgresRecordRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut record: Record,
    ) -> Result<Record, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.record_type.display_value(&record.value))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .fetch_one(&mut **postgres_tx)
        .await?;

        record.id = result.get::<i32, _>(0);
        Ok(record)
    }

    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        const CHUNK: usize = 500;
        let mut out = Vec::with_capacity(records.len());
        for chunk in records.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id) VALUES ",
            );
            let mut p = 1;
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!(
                    "(${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    p,
                    p + 1,
                    p + 2,
                    p + 3,
                    p + 4,
                    p + 5,
                    p + 6
                ));
                p += 7;
            }
            sql.push_str(" RETURNING id");

            let mut query = sqlx::query(AssertSqlSafe(sql));
            for r in chunk {
                query = query
                    .bind(&r.name)
                    .bind(r.record_type.to_string())
                    .bind(r.value.clone())
                    .bind(r.record_type.display_value(&r.value))
                    .bind(r.ttl)
                    .bind(r.priority)
                    .bind(r.zone_id);
            }
            let rows = query
                .fetch_all(&mut **postgres_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

            // Postgres returns RETURNING rows in the order the VALUES were given.
            for (r, row) in chunk.iter().zip(rows) {
                let mut rec = r.clone();
                rec.id = row.get::<i32, _>(0);
                out.push(rec);
            }
        }
        Ok(out)
    }

    async fn get(&self, id: i32) -> Result<Option<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            ?;

        Ok(record)
    }

    async fn get_with_zone(&self, id: i32) -> Result<Option<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record = sqlx::query_as::<_, RecordWithZone>(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE r.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(record)
    }

    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Record>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let record = sqlx::query_as::<_, Record>(AssertSqlSafe(format!("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = $1{}",lock_clause(lock_level))))
            .bind(id)
            .fetch_optional(&mut **postgres_tx)
            .await?;

        Ok(record)
    }

    async fn list(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records =
            sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 ORDER BY name")
                .bind(zone_id)
                .fetch_all(&mut *conn)
                .await
                ?;

        Ok(records)
    }

    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let records = sqlx::query_as::<_, Record>(AssertSqlSafe(
            format!("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 ORDER BY name{}",
            lock_clause(lock_level),
        )))
        .bind(zone_id)
        .fetch_all(&mut **postgres_tx)
        .await?;

        Ok(records)
    }

    async fn list_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        // Bind the canonical stored form as given: re-folding it here would miss
        // its own row, and the bare column lets idx_records_zone_name apply.
        let records = sqlx::query_as::<_, Record>(AssertSqlSafe(
            format!("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 AND name = $2 ORDER BY name{}",
            lock_clause(lock_level),
        )))
        .bind(zone_id)
        .bind(name)
        .fetch_all(&mut **postgres_tx)
        .await?;

        Ok(records)
    }

    async fn list_by_zone_ids(&self, zone_ids: &[i32]) -> Result<Vec<Record>, DatabaseError> {
        if zone_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut conn = self.pool.acquire().await?;

        const CHUNK: usize = 5000;
        let mut out = Vec::new();
        for chunk in zone_ids.chunks(CHUNK) {
            let mut sql = String::from(
                "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id IN (",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!("${}", i + 1));
            }
            sql.push(')');

            let mut query = sqlx::query_as::<_, Record>(AssertSqlSafe(sql));
            for zone_id in chunk {
                query = query.bind(zone_id);
            }
            let mut rows = query.fetch_all(&mut *conn).await?;
            out.append(&mut rows);
        }
        Ok(out)
    }

    async fn get_ds_name_without_ns_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<String>, DatabaseError> {
        let pg_tx = tx.as_postgres()?;

        let name = sqlx::query_scalar::<_, String>(
            "SELECT d.name FROM records d WHERE d.zone_id = $1 AND d.record_type = 'DS' AND NOT EXISTS (SELECT 1 FROM records n WHERE n.zone_id = $2 AND n.name = d.name AND n.record_type = 'NS') LIMIT 1",
        )
        .bind(zone_id)
        .bind(zone_id)
        .fetch_optional(&mut **pg_tx)
        .await?;

        Ok(name)
    }

    async fn list_by_names_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[OwnerName],
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }

        let postgres_tx = tx.as_postgres()?;

        // Only same-name rows can conflict, so lock just those.
        // One round-trip per chunk; keep it large (dominated bulk-import time on
        // networked backends). 5000 is well under the 65535 placeholder limit.
        const CHUNK: usize = 5000;
        let mut out = Vec::new();
        for chunk in names.chunks(CHUNK) {
            let mut sql = String::from(
                "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 AND name IN (",
            );
            for i in 0..chunk.len() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!("${}", i + 2));
            }
            sql.push(')');
            sql.push_str(lock_clause(lock_level));

            let mut query = sqlx::query_as::<_, Record>(AssertSqlSafe(sql)).bind(zone_id);
            for name in chunk {
                query = query.bind(name);
            }
            let mut rows = query.fetch_all(&mut **postgres_tx).await?;
            out.append(&mut rows);
        }
        Ok(out)
    }

    async fn list_by_filter_with_zone(
        &self,
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value = filter.value.as_deref().map(normalize_partial_value);
        let value_exact = filter.value.as_deref().map(str::trim);
        let search = like_pattern(filter.search.as_deref());
        let name_like_types = name_like_types_sql();
        let apex_owner = apex_owner_sql();

        let records = sqlx::query_as::<_, RecordWithZone>(AssertSqlSafe(format!(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE ($1::TEXT IS NULL OR LOWER(z.name) = LOWER($2))
              AND (
                    $3::TEXT IS NULL
                    OR LOWER(r.name) = LOWER($4)
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER($5)
              )
              AND ($6::TEXT IS NULL OR r.record_type = $7)
              AND ($8::TEXT IS NULL OR (CASE
                    WHEN r.record_type IN ({name_like_types}) THEN POSITION(LOWER($9) IN LOWER(r.display_value)) > 0
                    ELSE POSITION($31 IN r.display_value) > 0
              END))
              AND ($10::INT4 IS NULL OR r.ttl = $11)
              AND ($12::INT4 IS NULL OR r.ttl >= $13)
              AND ($14::INT4 IS NULL OR r.ttl <= $15)
              AND ($16::INT4 IS NULL OR r.priority = $17)
              AND ($18::INT4 IS NULL OR r.priority >= $19)
              AND ($20::INT4 IS NULL OR r.priority <= $21)
              AND (
                    $22::TEXT IS NULL
                    OR LOWER(z.name) LIKE LOWER($23) ESCAPE '\'
                    OR LOWER(r.name) LIKE LOWER($24) ESCAPE '\'
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) LIKE LOWER($25) ESCAPE '\'
                    OR LOWER(r.record_type) LIKE LOWER($26) ESCAPE '\'
                    OR LOWER(r.display_value) LIKE LOWER($27) ESCAPE '\'
            )
              AND (
                    $30::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = $30 AND p.zone_id = r.zone_id)
              )
            -- r.name ties across an RRset, so without r.id a plan change
            -- between two pages could drop or repeat a row.
            ORDER BY r.name, r.id
            LIMIT $28 OFFSET $29
            "#
        )))
        .bind(&filter.zone_name)
        .bind(&filter.zone_name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(&filter.record_type)
        .bind(&filter.record_type)
        .bind(&value)
        .bind(&value)
        .bind(filter.ttl)
        .bind(filter.ttl)
        .bind(filter.min_ttl)
        .bind(filter.min_ttl)
        .bind(filter.max_ttl)
        .bind(filter.max_ttl)
        .bind(filter.priority)
        .bind(filter.priority)
        .bind(filter.min_priority)
        .bind(filter.min_priority)
        .bind(filter.max_priority)
        .bind(filter.max_priority)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
        .bind(
            filter
                .offset
                .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
                .unwrap_or(0),
        )
        .bind(filter.scope_token_id)
        .bind(value_exact)
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    async fn count_by_filter(&self, filter: RecordFilter) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value = filter.value.as_deref().map(normalize_partial_value);
        let value_exact = filter.value.as_deref().map(str::trim);
        let search = like_pattern(filter.search.as_deref());
        let name_like_types = name_like_types_sql();
        let apex_owner = apex_owner_sql();

        let count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
            r#"
            SELECT COUNT(*)
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE ($1::TEXT IS NULL OR LOWER(z.name) = LOWER($2))
              AND (
                    $3::TEXT IS NULL
                    OR LOWER(r.name) = LOWER($4)
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER($5)
              )
              AND ($6::TEXT IS NULL OR r.record_type = $7)
              AND ($8::TEXT IS NULL OR (CASE
                    WHEN r.record_type IN ({name_like_types}) THEN POSITION(LOWER($9) IN LOWER(r.display_value)) > 0
                    ELSE POSITION($29 IN r.display_value) > 0
              END))
              AND ($10::INT4 IS NULL OR r.ttl = $11)
              AND ($12::INT4 IS NULL OR r.ttl >= $13)
              AND ($14::INT4 IS NULL OR r.ttl <= $15)
              AND ($16::INT4 IS NULL OR r.priority = $17)
              AND ($18::INT4 IS NULL OR r.priority >= $19)
              AND ($20::INT4 IS NULL OR r.priority <= $21)
              AND (
                    $22::TEXT IS NULL
                    OR LOWER(z.name) LIKE LOWER($23) ESCAPE '\'
                    OR LOWER(r.name) LIKE LOWER($24) ESCAPE '\'
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) LIKE LOWER($25) ESCAPE '\'
                    OR LOWER(r.record_type) LIKE LOWER($26) ESCAPE '\'
                    OR LOWER(r.display_value) LIKE LOWER($27) ESCAPE '\'
            )
              AND (
                    $28::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = $28 AND p.zone_id = r.zone_id)
              )
            "#
        )))
        .bind(&filter.zone_name)
        .bind(&filter.zone_name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(&filter.record_type)
        .bind(&filter.record_type)
        .bind(&value)
        .bind(&value)
        .bind(filter.ttl)
        .bind(filter.ttl)
        .bind(filter.min_ttl)
        .bind(filter.min_ttl)
        .bind(filter.max_ttl)
        .bind(filter.max_ttl)
        .bind(filter.priority)
        .bind(filter.priority)
        .bind(filter.min_priority)
        .bind(filter.min_priority)
        .bind(filter.max_priority)
        .bind(filter.max_priority)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(filter.scope_token_id)
        .bind(value_exact)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }

    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query(
            r#"
            UPDATE records
            SET name = $1, record_type = $2, value = $3, display_value = $4, ttl = $5, priority = $6, zone_id = $7
            WHERE id = $8
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.record_type.display_value(&record.value))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .bind(record.id)
        .execute(&mut **postgres_tx)
        .await?;

        Ok(record)
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

        sqlx::query("DELETE FROM records WHERE id = ANY($1)")
            .bind(ids)
            .execute(&mut **postgres_tx)
            .await?;
        Ok(())
    }
}
