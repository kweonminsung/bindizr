use async_trait::async_trait;
use bindizr_core::dns::name::OwnerName;
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::record::{Record, RecordWithZone},
    repository::{
        LockLevel, RecordFilter, RecordRepository, RepositoryTx,
        sql::{
            apex_owner_sql, concat_pipes, grant_record_match_sql, like_pattern,
            name_like_types_sql, partial_term,
        },
    },
};

pub(crate) struct SqliteRecordRepository {
    pool: Pool<Sqlite>,
}

impl SqliteRecordRepository {
    /// Create a repository for records using the supplied pool.
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordRepository for SqliteRecordRepository {
    /// Insert a batch of records in the current transaction.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // Statement count drives bulk-insert time, but the gain flattens by ~500
        // rows; 8 binds per row leaves room under SQLite's 32766 limit.
        const CHUNK: usize = 500;
        let mut out = Vec::with_capacity(records.len());
        for chunk in records.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id, created_at) VALUES ",
            );
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 {
                    "(?, ?, ?, ?, ?, ?, ?, ?)"
                } else {
                    ",(?, ?, ?, ?, ?, ?, ?, ?)"
                });
            }

            let now = Utc::now();
            let mut query = sqlx::query(AssertSqlSafe(sql));
            for r in chunk {
                query = query
                    .bind(&r.name)
                    .bind(r.record_type.to_string())
                    .bind(r.value.clone())
                    .bind(r.record_type.display_value(&r.value))
                    .bind(r.ttl)
                    .bind(r.priority)
                    .bind(r.zone_id)
                    .bind(now);
            }
            let result = query
                .execute(&mut **sqlite_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

            // SQLite assigns contiguous rowids within a single insert; the last
            // one is `last_insert_rowid()`, so the chunk spans first..=last.
            let last = result.last_insert_rowid() as i32;
            let first = last - chunk.len() as i32 + 1;
            for (offset, r) in chunk.iter().enumerate() {
                let mut rec = r.clone();
                rec.id = first + offset as i32;
                rec.created_at = now;
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Find a record by ID.
    async fn get(&self, id: i32) -> Result<Option<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            ?;

        Ok(record)
    }

    /// Find a record with its zone metadata.
    async fn get_with_zone(&self, id: i32) -> Result<Option<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record = sqlx::query_as::<_, RecordWithZone>(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE r.id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(record)
    }

    /// Find a record by ID in the current transaction.
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        _lock_level: LockLevel,
    ) -> Result<Option<Record>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut **sqlite_tx)
            .await?;

        Ok(record)
    }

    /// List records for a zone in the current transaction.
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        _lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name, id",
        )
        .bind(zone_id)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(records)
    }

    /// List records at an owner name in a zone in the current transaction.
    async fn list_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
        _lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // Bind the canonical stored form as given: re-folding it here would miss
        // its own row, and the bare column lets idx_records_zone_name apply.
        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name = ? ORDER BY name, id",
        )
        .bind(zone_id)
        .bind(name)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(records)
    }

    /// Find an owner with a DS record but no NS delegation in the current transaction.
    async fn get_ds_name_without_ns_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<String>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let name = sqlx::query_scalar::<_, String>(
            "SELECT d.name FROM records d WHERE d.zone_id = ? AND d.record_type = 'DS' AND NOT EXISTS (SELECT 1 FROM records n WHERE n.zone_id = ? AND n.name = d.name AND n.record_type = 'NS') LIMIT 1",
        )
        .bind(zone_id)
        .bind(zone_id)
        .fetch_optional(&mut **sqlite_tx)
        .await?;

        Ok(name)
    }

    /// List records at the requested owner names in a zone in the current transaction.
    async fn list_by_names_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[OwnerName],
        _lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }

        let sqlite_tx = tx.as_sqlite()?;

        // Only same-name rows can conflict, so load just those, matching the
        // stored names as given so idx_records_zone_name applies. Chunk the IN
        // list to stay under SQLite's bind-variable limit.
        const CHUNK: usize = 400;
        let mut out = Vec::new();
        for chunk in names.chunks(CHUNK) {
            let mut sql = String::from(
                "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name IN (",
            );
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 { "?" } else { ",?" });
            }
            sql.push(')');

            let mut query = sqlx::query_as::<_, Record>(AssertSqlSafe(sql)).bind(zone_id);
            for name in chunk {
                query = query.bind(name);
            }
            let mut rows = query.fetch_all(&mut **sqlite_tx).await?;
            out.append(&mut rows);
        }
        Ok(out)
    }

    /// List matching records with their zone metadata.
    async fn list_by_filter_with_zone(
        &self,
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value = filter.value.as_deref().map(partial_term);
        let value_exact = filter.value.as_deref().map(str::trim);
        let search = like_pattern(filter.search.as_deref());
        let name_like_types = name_like_types_sql();
        let apex_owner = apex_owner_sql();
        let order_by = filter.sort.order_by_sql(filter.order);
        let grant_match = grant_record_match_sql("r", Some("record_type"), concat_pipes);
        let query = sqlx::query_as::<_, RecordWithZone>(AssertSqlSafe(format!(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE (? IS NULL OR r.zone_id = (SELECT id FROM zones WHERE name = ?))
              AND (
                    ? IS NULL
                    OR LOWER(r.name) = LOWER(?)
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER(?)
              )
              AND (? IS NULL OR r.record_type = ?)
              AND (? IS NULL OR (CASE
                    WHEN r.record_type IN ({name_like_types}) THEN INSTR(LOWER(r.display_value), LOWER(?)) > 0
                    ELSE INSTR(r.display_value, ?) > 0
              END))
              AND (? IS NULL OR r.ttl = ?)
              AND (? IS NULL OR r.ttl >= ?)
              AND (? IS NULL OR r.ttl <= ?)
              AND (? IS NULL OR r.priority = ?)
              AND (? IS NULL OR r.priority >= ?)
              AND (? IS NULL OR r.priority <= ?)
              AND (
                    ? IS NULL
                    OR LOWER(z.name) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(r.name) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(r.record_type) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(r.display_value) LIKE LOWER(?) ESCAPE '\'
            )
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM token_grants p
                               WHERE p.api_token_id = ? AND p.zone_id = r.zone_id
                                 AND {grant_match})
              )
            {order_by}
            LIMIT ? OFFSET ?
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
        .bind(value_exact)
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
        .bind(&search);
        let records = query
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

    /// Count records matching the filter.
    async fn count_by_filter(&self, filter: RecordFilter) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value = filter.value.as_deref().map(partial_term);
        let value_exact = filter.value.as_deref().map(str::trim);
        let search = like_pattern(filter.search.as_deref());
        let name_like_types = name_like_types_sql();
        let apex_owner = apex_owner_sql();
        let grant_match = grant_record_match_sql("r", Some("record_type"), concat_pipes);
        let query = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
            r#"
            SELECT COUNT(*)
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE (? IS NULL OR r.zone_id = (SELECT id FROM zones WHERE name = ?))
              AND (
                    ? IS NULL
                    OR LOWER(r.name) = LOWER(?)
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER(?)
              )
              AND (? IS NULL OR r.record_type = ?)
              AND (? IS NULL OR (CASE
                    WHEN r.record_type IN ({name_like_types}) THEN INSTR(LOWER(r.display_value), LOWER(?)) > 0
                    ELSE INSTR(r.display_value, ?) > 0
              END))
              AND (? IS NULL OR r.ttl = ?)
              AND (? IS NULL OR r.ttl >= ?)
              AND (? IS NULL OR r.ttl <= ?)
              AND (? IS NULL OR r.priority = ?)
              AND (? IS NULL OR r.priority >= ?)
              AND (? IS NULL OR r.priority <= ?)
              AND (
                    ? IS NULL
                    OR LOWER(z.name) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(r.name) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(r.record_type) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(r.display_value) LIKE LOWER(?) ESCAPE '\'
            )
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM token_grants p
                               WHERE p.api_token_id = ? AND p.zone_id = r.zone_id
                                 AND {grant_match})
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
        .bind(value_exact)
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
        .bind(filter.scope_token_id);
        let count = query.fetch_one(&mut *conn).await?;

        Ok(count as u64)
    }

    /// Update a record in the current transaction.
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query(
            r#"
            UPDATE records 
            SET name = ?, record_type = ?, value = ?, display_value = ?, ttl = ?, priority = ?, zone_id = ?
            WHERE id = ?
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
        .execute(&mut **sqlite_tx)
        .await?;

        Ok(record)
    }

    /// Delete the records with the supplied IDs in the current transaction.
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
            let mut sql = String::from("DELETE FROM records WHERE id IN (");
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
}
