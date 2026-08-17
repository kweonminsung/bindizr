use async_trait::async_trait;
use bindizr_core::dns::name::OwnerName;
use sqlx::{AssertSqlSafe, Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::record::{Record, RecordWithZone},
    repository::{
        LockLevel, RecordFilter, RecordRepository, RepositoryTx,
        sql::{apex_owner_sql, like_pattern, name_like_types_sql, normalize_partial_value},
    },
};

/// SQLite-backed implementation of `RecordRepository`.
pub(crate) struct SqliteRecordRepository {
    pool: Pool<Sqlite>,
}

impl SqliteRecordRepository {
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordRepository for SqliteRecordRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut record: Record,
    ) -> Result<Record, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.record_type.display_value(&record.value))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(&mut **sqlite_tx)
        .await?;

        record.id = result.last_insert_rowid() as i32;
        Ok(record)
    }

    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        // 7 binds per row; stays under SQLite's conservative 999-bind limit.
        const CHUNK: usize = 142;
        let mut out = Vec::with_capacity(records.len());
        for chunk in records.chunks(CHUNK) {
            let mut sql = String::from(
                "INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id) VALUES ",
            );
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 {
                    "(?, ?, ?, ?, ?, ?, ?)"
                } else {
                    ",(?, ?, ?, ?, ?, ?, ?)"
                });
            }

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
                out.push(rec);
            }
        }
        Ok(out)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            ?;

        Ok(record)
    }

    async fn get_by_id_with_zone(&self, id: i32) -> Result<Option<RecordWithZone>, DatabaseError> {
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

    async fn get_by_id_tx(
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

    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records =
            sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name")
                .bind(zone_id)
                .fetch_all(&mut *conn)
                .await
                ?;

        Ok(records)
    }

    async fn list_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        _lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name",
        )
        .bind(zone_id)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(records)
    }

    async fn list_by_zone_id_and_name_tx(
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
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name = ? ORDER BY name",
        )
        .bind(zone_id)
        .bind(name)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(records)
    }

    async fn list_by_zone_ids(&self, zone_ids: &[i32]) -> Result<Vec<Record>, DatabaseError> {
        if zone_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut conn = self.pool.acquire().await?;

        const CHUNK: usize = 400;
        let mut out = Vec::new();
        for chunk in zone_ids.chunks(CHUNK) {
            let mut sql = String::from(
                "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id IN (",
            );
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 { "?" } else { ",?" });
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

    async fn list_by_zone_id_and_names_tx(
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
        let query = sqlx::query_as::<_, RecordWithZone>(AssertSqlSafe(format!(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE (? IS NULL OR LOWER(z.name) = LOWER(?))
              AND (
                    ? IS NULL
                    OR LOWER(r.name) = LOWER(?)
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER(?)
              )
              AND (? IS NULL OR LOWER(r.record_type) = LOWER(?))
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
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = ? AND p.zone_id = r.zone_id)
              )
            -- r.name ties across an RRset, so without r.id a plan change
            -- between two pages could drop or repeat a row.
            ORDER BY r.name, r.id
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

    async fn count_by_filter(&self, filter: RecordFilter) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value = filter.value.as_deref().map(normalize_partial_value);
        let value_exact = filter.value.as_deref().map(str::trim);
        let search = like_pattern(filter.search.as_deref());
        let name_like_types = name_like_types_sql();
        let apex_owner = apex_owner_sql();
        let query = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
            r#"
            SELECT COUNT(*)
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE (? IS NULL OR LOWER(z.name) = LOWER(?))
              AND (
                    ? IS NULL
                    OR LOWER(r.name) = LOWER(?)
                    OR LOWER(CASE WHEN r.name = {apex_owner} THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER(?)
              )
              AND (? IS NULL OR LOWER(r.record_type) = LOWER(?))
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
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = ? AND p.zone_id = r.zone_id)
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
