use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::record::RecordId;
use bindizr_core::model::zone::ZoneId;
use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Sqlite, Transaction};

use crate::error::DatabaseError;
use crate::model::record::{Record, RecordType, RecordWithZone};
use crate::record::RecordFilter;
use crate::{LockLevel, sql};

/// Insert a batch of records in the current transaction.
pub(crate) async fn create_many_tx(
    tx: &mut Transaction<'_, Sqlite>,
    records: &[Record],
) -> Result<Vec<Record>, DatabaseError> {
    // Statement count drives bulk-insert time, but the gain flattens by ~500
    // rows; 8 binds per row leaves room under SQLite's 32766 limit.
    const CHUNK: usize = 500;
    let mut created_records = Vec::with_capacity(records.len());

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

        for record in chunk {
            query = query
                .bind(&record.name)
                .bind(record.record_type.as_str())
                .bind(record.value.clone())
                .bind(record.record_type.display_value(&record.value))
                .bind(record.ttl)
                .bind(record.priority)
                .bind(record.zone_id)
                .bind(now);
        }

        let result = query.execute(&mut **tx).await?;

        // SQLite assigns contiguous rowids within a single insert; the last
        // one is `last_insert_rowid()`, so the chunk spans first..=last.
        let last = super::last_insert_id(&result)?;
        let first = last - chunk.len() as i32 + 1;

        for (offset, record) in chunk.iter().enumerate() {
            let mut created_record = record.clone();
            created_record.id = RecordId::from(first + offset as i32);
            created_record.created_at = now;
            created_records.push(created_record);
        }
    }

    Ok(created_records)
}

/// Find a record by ID.
pub(crate) async fn get(
    pool: &Pool<Sqlite>,
    id: RecordId,
) -> Result<Option<Record>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *connection)
        .await
        ?;

    Ok(record)
}

/// Find a record with its zone metadata.
pub(crate) async fn get_with_zone(
    pool: &Pool<Sqlite>,
    id: RecordId,
) -> Result<Option<RecordWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

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
    .fetch_optional(&mut *connection)
    .await?;

    Ok(record)
}

/// Find a record by ID in the current transaction.
pub(crate) async fn get_tx(
    tx: &mut Transaction<'_, Sqlite>,
    id: RecordId,
    _lock_level: LockLevel,
) -> Result<Option<Record>, DatabaseError> {
    let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;

    Ok(record)
}

/// List records for a zone in the current transaction.
pub(crate) async fn list_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    _lock_level: LockLevel,
) -> Result<Vec<Record>, DatabaseError> {
    let records = sqlx::query_as::<_, Record>(
        "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name, id",
    )
    .bind(zone_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(records)
}

/// List records at an owner name in a zone in the current transaction.
pub(crate) async fn list_by_name_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    name: &OwnerName,
    _lock_level: LockLevel,
) -> Result<Vec<Record>, DatabaseError> {
    // Bind the canonical stored form as given: re-folding it here would miss
    // its own row, and the bare column lets idx_records_zone_name apply.
    let records = sqlx::query_as::<_, Record>(
        "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name = ? ORDER BY name, id",
    )
    .bind(zone_id)
    .bind(name)
    .fetch_all(&mut **tx)
    .await?;

    Ok(records)
}

/// List the records of the given types in the current transaction.
pub(crate) async fn list_by_record_types_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    record_types: &[RecordType],
) -> Result<Vec<Record>, DatabaseError> {
    if record_types.is_empty() {
        return Ok(Vec::new());
    }

    let mut sql = String::from(
        "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND record_type IN (",
    );

    for i in 0..record_types.len() {
        sql.push_str(if i == 0 {
            "?"
        } else {
            ",?"
        });
    }

    sql.push_str(") ORDER BY name, id");

    let mut query = sqlx::query_as::<_, Record>(AssertSqlSafe(sql)).bind(zone_id);

    for record_type in record_types {
        query = query.bind(record_type.as_str());
    }

    let records = query.fetch_all(&mut **tx).await?;

    Ok(records)
}

/// List the distinct owner names of a zone in the current transaction.
pub(crate) async fn list_names_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
) -> Result<Vec<OwnerName>, DatabaseError> {
    let names =
        sqlx::query_scalar::<_, OwnerName>("SELECT DISTINCT name FROM records WHERE zone_id = ?")
            .bind(zone_id)
            .fetch_all(&mut **tx)
            .await?;

    Ok(names)
}

/// List records at the requested owner names in a zone in the current transaction.
pub(crate) async fn list_by_names_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    names: &[OwnerName],
    _lock_level: LockLevel,
) -> Result<Vec<Record>, DatabaseError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }

    // Load only same-name conflicts using idx_records_zone_name;
    // chunk the IN list below SQLite's bind-variable limit.
    const CHUNK: usize = 400;
    let mut records = Vec::new();

    for chunk in names.chunks(CHUNK) {
        let mut sql = String::from(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? AND name IN (",
        );

        for i in 0..chunk.len() {
            sql.push_str(if i == 0 {
                "?"
            } else {
                ",?"
            });
        }

        sql.push(')');

        let mut query = sqlx::query_as::<_, Record>(AssertSqlSafe(sql)).bind(zone_id);

        for name in chunk {
            query = query.bind(name);
        }

        let mut rows = query.fetch_all(&mut **tx).await?;
        records.append(&mut rows);
    }

    Ok(records)
}

/// List matching records with their zone metadata.
pub(crate) async fn list_by_filter_with_zone(
    pool: &Pool<Sqlite>,
    filter: RecordFilter,
) -> Result<Vec<RecordWithZone>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let value = filter.value.as_deref().map(sql::partial_term);
    let value_exact = filter.value.as_deref().map(str::trim);
    let search = sql::like_pattern(filter.search.as_deref());
    let name_like_types = sql::name_like_types_sql();
    let apex_owner = sql::apex_owner_sql();

    // Only fixed SQL fragments are interpolated; caller values stay in bindings.
    let order_by = filter.sort.order_by_sql(filter.order);
    let grant_match = sql::grant_record_match_sql("r", Some("record_type"), sql::concat_pipes);
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
                OR EXISTS (SELECT 1 FROM role_grants p
                           WHERE p.role_id = ? AND (p.zone_id IS NULL OR p.zone_id = r.zone_id)
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
    .bind(filter.record_type)
    .bind(filter.record_type)
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
        .bind(filter.scope_role_id)
        .bind(filter.scope_role_id)
        .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
        .bind(
            filter
                .offset
                .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
                .unwrap_or(0),
        )
        .fetch_all(&mut *connection)
        .await?;

    Ok(records)
}

/// Count a zone's records in the current transaction.
pub(crate) async fn count_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
) -> Result<u64, DatabaseError> {
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records WHERE zone_id = ?")
        .bind(zone_id)
        .fetch_one(&mut **tx)
        .await?;

    Ok(count as u64)
}

/// Count records matching the filter.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    filter: RecordFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let value = filter.value.as_deref().map(sql::partial_term);
    let value_exact = filter.value.as_deref().map(str::trim);
    let search = sql::like_pattern(filter.search.as_deref());
    let name_like_types = sql::name_like_types_sql();
    let apex_owner = sql::apex_owner_sql();
    let grant_match = sql::grant_record_match_sql("r", Some("record_type"), sql::concat_pipes);
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
                OR EXISTS (SELECT 1 FROM role_grants p
                           WHERE p.role_id = ? AND (p.zone_id IS NULL OR p.zone_id = r.zone_id)
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
    .bind(filter.scope_role_id)
    .bind(filter.scope_role_id);

    let count = query.fetch_one(&mut *connection).await?;

    Ok(count as u64)
}

/// Update a record in the current transaction.
pub(crate) async fn update_tx(
    tx: &mut Transaction<'_, Sqlite>,
    record: Record,
) -> Result<Record, DatabaseError> {
    sqlx::query(
        r#"
        UPDATE records 
        SET name = ?, record_type = ?, value = ?, display_value = ?, ttl = ?, priority = ?, zone_id = ?
        WHERE id = ?
        "#,
    )
    .bind(&record.name)
    .bind(record.record_type.as_str())
    .bind(&record.value)
    .bind(record.record_type.display_value(&record.value))
    .bind(record.ttl)
    .bind(record.priority)
    .bind(record.zone_id)
    .bind(record.id)
    .execute(&mut **tx)
    .await?;

    Ok(record)
}

/// Delete the records with the supplied IDs in the current transaction.
pub(crate) async fn delete_many_tx(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[RecordId],
) -> Result<(), DatabaseError> {
    if ids.is_empty() {
        return Ok(());
    }

    // One bind per id; keep the count under SQLite's conservative limit.
    const CHUNK: usize = 900;

    for chunk in ids.chunks(CHUNK) {
        let mut sql = String::from("DELETE FROM records WHERE id IN (");

        for i in 0..chunk.len() {
            sql.push_str(if i == 0 {
                "?"
            } else {
                ",?"
            });
        }

        sql.push(')');

        let mut query = sqlx::query(AssertSqlSafe(sql));

        for id in chunk {
            query = query.bind(id);
        }

        query.execute(&mut **tx).await?;
    }

    Ok(())
}
