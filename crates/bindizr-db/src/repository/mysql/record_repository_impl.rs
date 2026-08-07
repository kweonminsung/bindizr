use async_trait::async_trait;
use bindizr_core::dns::record::display_record_value;
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::record::{Record, RecordType, RecordWithZone},
    repository::{RecordFilter, RecordRepository, RepositoryTx},
};

/// MySQL-backed implementation of `RecordRepository`.
pub struct MySqlRecordRepository {
    pool: Pool<MySql>,
}

impl MySqlRecordRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: Pool<MySql>) -> Self {
        MySqlRecordRepository { pool }
    }
}

#[async_trait]
impl RecordRepository for MySqlRecordRepository {
    async fn create(&self, mut record: Record) -> Result<Record, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(display_record_value(&record.value, &record.record_type))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(&mut *conn)
        .await?;

        record.id = result.last_insert_id() as i32;

        Ok(record)
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut record: Record,
    ) -> Result<Record, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, display_value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(display_record_value(&record.value, &record.record_type))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(&mut **mysql_tx)
        .await?;

        record.id = result.last_insert_id() as i32;
        Ok(record)
    }

    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // Ids in a multi-row insert step by @@auto_increment_increment,
        // which is >1 on multi-primary replication setups.
        let increment =
            sqlx::query_scalar::<_, i64>("SELECT CAST(@@auto_increment_increment AS SIGNED)")
                .fetch_one(&mut **mysql_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?
                .max(1) as i32;

        const CHUNK: usize = 500;
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
                    .bind(r.name.clone())
                    .bind(r.record_type.to_string())
                    .bind(r.value.clone())
                    .bind(display_record_value(&r.value, &r.record_type))
                    .bind(r.ttl)
                    .bind(r.priority)
                    .bind(r.zone_id);
            }
            let result = query
                .execute(&mut **mysql_tx)
                .await
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

            // MySQL returns the id of the FIRST row of a multi-row insert; the
            // ids are contiguous by `increment` for a simple insert under every
            // innodb_autoinc_lock_mode.
            let first = result.last_insert_id() as i32;
            for (offset, r) in chunk.iter().enumerate() {
                let mut rec = r.clone();
                rec.id = first + offset as i32 * increment;
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
    ) -> Result<Option<Record>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ? FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **mysql_tx)
            .await?;

        Ok(record)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records =
            sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name")
                .bind(zone_id)
                .fetch_all(&mut *conn)
                .await
                ?;

        Ok(records)
    }

    async fn get_by_zone_id_with_zone(
        &self,
        zone_id: i32,
    ) -> Result<Vec<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records = sqlx::query_as::<_, RecordWithZone>(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE r.zone_id = ?
            ORDER BY r.name
            "#,
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    async fn get_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name FOR UPDATE",
        )
        .bind(zone_id)
        .fetch_all(&mut **mysql_tx)
        .await?;

        Ok(records)
    }

    async fn get_by_zone_id_and_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &str,
    ) -> Result<Vec<Record>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        // Owner names are stored lowercase, so match against a lowercased bind
        // and keep the column function-free so idx_records_zone_name is used.
        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name = ? ORDER BY name FOR UPDATE",
        )
        .bind(zone_id)
        .bind(name.to_lowercase())
        .fetch_all(&mut **mysql_tx)
        .await?;

        Ok(records)
    }

    async fn get_by_zone_ids(&self, zone_ids: &[i32]) -> Result<Vec<Record>, DatabaseError> {
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

    async fn get_by_zone_id_and_names_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[String],
    ) -> Result<Vec<Record>, DatabaseError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }

        let mysql_tx = tx.as_mysql()?;

        // Only same-name rows can conflict, so match names lowercased (keeping the
        // column function-free so idx_records_zone_name is used) and lock just those.
        // One round-trip per chunk; keep it large (chunk size dominated bulk-import
        // time). 5000 is well under the 65535 placeholder limit.
        const CHUNK: usize = 5000;
        let mut out = Vec::new();
        for chunk in names.chunks(CHUNK) {
            let mut sql = String::from(
                "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name IN (",
            );
            for i in 0..chunk.len() {
                sql.push_str(if i == 0 { "?" } else { ",?" });
            }
            sql.push_str(") FOR UPDATE");

            let mut query = sqlx::query_as::<_, Record>(AssertSqlSafe(sql)).bind(zone_id);
            for name in chunk {
                query = query.bind(name.to_lowercase());
            }
            let mut rows = query.fetch_all(&mut **mysql_tx).await?;
            out.append(&mut rows);
        }
        Ok(out)
    }

    async fn get(
        &self,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value_filter = if record_type.is_name_like_value() {
            "AND (? IS NULL OR BINARY LOWER(value) = BINARY LOWER(?))"
        } else {
            "AND (? IS NULL OR BINARY value = BINARY ?)"
        };

        let query = format!(
            r#"
            SELECT id, name, record_type, value, ttl, priority, created_at, zone_id
            FROM records
            WHERE (? IS NULL OR zone_id = ?)
              AND LOWER(name) = LOWER(?)
              AND record_type = ?
              {value_filter}
              AND (? = 0 OR priority = ? OR (priority IS NULL AND ? IS NULL))
            "#
        );

        let record = sqlx::query_as::<_, Record>(AssertSqlSafe(query))
            .bind(zone_id)
            .bind(zone_id)
            .bind(name)
            .bind(record_type.to_string())
            .bind(value)
            .bind(value)
            .bind(if match_priority { 1 } else { 0 })
            .bind(priority)
            .bind(priority)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(record)
    }

    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;
        let value_filter = if record_type.is_name_like_value() {
            "AND (? IS NULL OR BINARY LOWER(value) = BINARY LOWER(?))"
        } else {
            "AND (? IS NULL OR BINARY value = BINARY ?)"
        };

        let query = format!(
            r#"
            SELECT id, name, record_type, value, ttl, priority, created_at, zone_id
            FROM records
            WHERE (? IS NULL OR zone_id = ?)
              AND LOWER(name) = LOWER(?)
              AND record_type = ?
              {value_filter}
              AND (? = 0 OR priority = ? OR (priority IS NULL AND ? IS NULL))
            FOR UPDATE
            "#
        );

        let record = sqlx::query_as::<_, Record>(AssertSqlSafe(query))
            .bind(zone_id)
            .bind(zone_id)
            .bind(name)
            .bind(record_type.to_string())
            .bind(value)
            .bind(value)
            .bind(if match_priority { 1 } else { 0 })
            .bind(priority)
            .bind(priority)
            .fetch_optional(&mut **mysql_tx)
            .await?;

        Ok(record)
    }

    async fn get_all(&self) -> Result<Vec<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records ORDER BY name")
            .fetch_all(&mut *conn)
            .await
            ?;

        Ok(records)
    }

    async fn get_all_with_zone(&self) -> Result<Vec<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records = sqlx::query_as::<_, RecordWithZone>(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            ORDER BY r.name
            "#,
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    async fn get_by_filter_with_zone(
        &self,
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let value = filter.value.as_deref().map(normalize_partial_value);
        let value_exact = filter.value.as_deref().map(str::trim);
        let search = like_pattern(filter.search.as_deref());
        let zone_ids_clause = match filter.zone_ids.as_deref() {
            None => String::new(),
            Some([]) => "AND 1 = 0".to_string(),
            Some(ids) => format!("AND r.zone_id IN ({})", vec!["?"; ids.len()].join(",")),
        };

        let mut query = sqlx::query_as::<_, RecordWithZone>(AssertSqlSafe(format!(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE (? IS NULL OR LOWER(z.name) = LOWER(?))
              AND (
                    ? IS NULL
                    OR LOWER(r.name) = LOWER(?)
                    OR LOWER(CASE WHEN r.name = '@' THEN CONCAT(z.name, '.') ELSE CONCAT(r.name, '.', z.name, '.') END) = LOWER(?)
              )
              AND (? IS NULL OR LOWER(r.record_type) = LOWER(?))
              AND (? IS NULL OR (CASE
                    WHEN r.record_type IN ('CNAME','NS','PTR','MX','SRV') THEN LOCATE(LOWER(?), LOWER(r.display_value)) > 0
                    ELSE LOCATE(BINARY ?, BINARY r.display_value) > 0
              END))
              AND (? IS NULL OR r.ttl = ?)
              AND (? IS NULL OR r.ttl >= ?)
              AND (? IS NULL OR r.ttl <= ?)
              AND (? IS NULL OR r.priority = ?)
              AND (? IS NULL OR r.priority >= ?)
              AND (? IS NULL OR r.priority <= ?)
              AND (
                    ? IS NULL
                    OR LOWER(z.name) LIKE LOWER(?)
                    OR LOWER(r.name) LIKE LOWER(?)
                    OR LOWER(CASE WHEN r.name = '@' THEN CONCAT(z.name, '.') ELSE CONCAT(r.name, '.', z.name, '.') END) LIKE LOWER(?)
                    OR LOWER(r.record_type) LIKE LOWER(?)
                    OR LOWER(r.display_value) LIKE LOWER(?)
            )
            {zone_ids_clause}
            ORDER BY r.name
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
        if let Some(ids) = &filter.zone_ids {
            for zone_id in ids {
                query = query.bind(zone_id);
            }
        }
        let records = query
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
        let zone_ids_clause = match filter.zone_ids.as_deref() {
            None => String::new(),
            Some([]) => "AND 1 = 0".to_string(),
            Some(ids) => format!("AND r.zone_id IN ({})", vec!["?"; ids.len()].join(",")),
        };

        let mut query = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
            r#"
            SELECT COUNT(*)
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE (? IS NULL OR LOWER(z.name) = LOWER(?))
              AND (
                    ? IS NULL
                    OR LOWER(r.name) = LOWER(?)
                    OR LOWER(CASE WHEN r.name = '@' THEN CONCAT(z.name, '.') ELSE CONCAT(r.name, '.', z.name, '.') END) = LOWER(?)
              )
              AND (? IS NULL OR LOWER(r.record_type) = LOWER(?))
              AND (? IS NULL OR (CASE
                    WHEN r.record_type IN ('CNAME','NS','PTR','MX','SRV') THEN LOCATE(LOWER(?), LOWER(r.display_value)) > 0
                    ELSE LOCATE(BINARY ?, BINARY r.display_value) > 0
              END))
              AND (? IS NULL OR r.ttl = ?)
              AND (? IS NULL OR r.ttl >= ?)
              AND (? IS NULL OR r.ttl <= ?)
              AND (? IS NULL OR r.priority = ?)
              AND (? IS NULL OR r.priority >= ?)
              AND (? IS NULL OR r.priority <= ?)
              AND (
                    ? IS NULL
                    OR LOWER(z.name) LIKE LOWER(?)
                    OR LOWER(r.name) LIKE LOWER(?)
                    OR LOWER(CASE WHEN r.name = '@' THEN CONCAT(z.name, '.') ELSE CONCAT(r.name, '.', z.name, '.') END) LIKE LOWER(?)
                    OR LOWER(r.record_type) LIKE LOWER(?)
                    OR LOWER(r.display_value) LIKE LOWER(?)
            )
            {zone_ids_clause}
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
        if let Some(ids) = &filter.zone_ids {
            for zone_id in ids {
                query = query.bind(zone_id);
            }
        }
        let count = query.fetch_one(&mut *conn).await?;

        Ok(count as u64)
    }

    async fn update(&self, record: Record) -> Result<Record, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

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
        .bind(display_record_value(&record.value, &record.record_type))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .bind(record.id)
        .execute(&mut *conn)
        .await?;

        Ok(record)
    }

    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

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
        .bind(display_record_value(&record.value, &record.record_type))
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .bind(record.id)
        .execute(&mut **mysql_tx)
        .await?;

        Ok(record)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(&mut **mysql_tx)
            .await?;
        Ok(())
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
            let mut sql = String::from("DELETE FROM records WHERE id IN (");
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
}

fn normalize_partial_value(value: &str) -> String {
    value.trim().trim_end_matches('.').to_string()
}

fn like_pattern(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{}%", value.trim_end_matches('.')))
}
