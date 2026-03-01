use super::error::XfrError;
use crate::database::{get_pool, DatabasePool};
use sqlx::{MySql, Pool, Postgres, Sqlite};

#[derive(Debug, Clone)]
pub struct ZoneChange {
    pub serial: u32,
    pub operation: String, // "ADD" or "DEL"
    pub record_name: String,
    pub record_type: String,
    pub record_value: String,
    pub record_ttl: Option<i32>,
    pub record_priority: Option<i32>,
}

/// Get zone changes between two serials for IXFR
pub async fn get_zone_changes(
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    let pool = get_pool();

    match pool {
        DatabasePool::MySQL(p) => get_zone_changes_mysql(p, zone_id, from_serial, to_serial).await,
        DatabasePool::PostgreSQL(p) => {
            get_zone_changes_postgres(p, zone_id, from_serial, to_serial).await
        }
        DatabasePool::SQLite(p) => {
            get_zone_changes_sqlite(p, zone_id, from_serial, to_serial).await
        }
    }
}

async fn get_zone_changes_mysql(
    pool: &Pool<MySql>,
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    let from_serial_i32 = from_serial as i32;
    let to_serial_i32 = to_serial as i32;

    #[derive(sqlx::FromRow)]
    struct ZoneChangeRow {
        serial: i32,
        operation: String,
        record_name: String,
        record_type: String,
        record_value: String,
        record_ttl: Option<i32>,
        record_priority: Option<i32>,
    }

    let rows = sqlx::query_as::<_, ZoneChangeRow>(
        r#"
        SELECT serial, operation, record_name, record_type, record_value, record_ttl, record_priority
        FROM zone_changes
        WHERE zone_id = ? AND serial > ? AND serial <= ?
        ORDER BY serial, id
        "#
    )
    .bind(zone_id)
    .bind(from_serial_i32)
    .bind(to_serial_i32)
    .fetch_all(pool)
    .await
    .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    let changes = rows
        .into_iter()
        .map(|row| ZoneChange {
            serial: row.serial as u32,
            operation: row.operation,
            record_name: row.record_name,
            record_type: row.record_type,
            record_value: row.record_value,
            record_ttl: row.record_ttl,
            record_priority: row.record_priority,
        })
        .collect();

    Ok(changes)
}

async fn get_zone_changes_postgres(
    pool: &Pool<Postgres>,
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    let from_serial_i32 = from_serial as i32;
    let to_serial_i32 = to_serial as i32;

    #[derive(sqlx::FromRow)]
    struct ZoneChangeRow {
        serial: i32,
        operation: String,
        record_name: String,
        record_type: String,
        record_value: String,
        record_ttl: Option<i32>,
        record_priority: Option<i32>,
    }

    let rows = sqlx::query_as::<_, ZoneChangeRow>(
        r#"
        SELECT serial, operation, record_name, record_type, record_value, record_ttl, record_priority
        FROM zone_changes
        WHERE zone_id = $1 AND serial > $2 AND serial <= $3
        ORDER BY serial, id
        "#
    )
    .bind(zone_id)
    .bind(from_serial_i32)
    .bind(to_serial_i32)
    .fetch_all(pool)
    .await
    .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    let changes = rows
        .into_iter()
        .map(|row| ZoneChange {
            serial: row.serial as u32,
            operation: row.operation,
            record_name: row.record_name,
            record_type: row.record_type,
            record_value: row.record_value,
            record_ttl: row.record_ttl,
            record_priority: row.record_priority,
        })
        .collect();

    Ok(changes)
}

async fn get_zone_changes_sqlite(
    pool: &Pool<Sqlite>,
    zone_id: i32,
    from_serial: u32,
    to_serial: u32,
) -> Result<Vec<ZoneChange>, XfrError> {
    let from_serial_i32 = from_serial as i32;
    let to_serial_i32 = to_serial as i32;

    #[derive(sqlx::FromRow)]
    struct ZoneChangeRow {
        serial: i32,
        operation: String,
        record_name: String,
        record_type: String,
        record_value: String,
        record_ttl: Option<i32>,
        record_priority: Option<i32>,
    }

    let rows = sqlx::query_as::<_, ZoneChangeRow>(
        r#"
        SELECT serial, operation, record_name, record_type, record_value, record_ttl, record_priority
        FROM zone_changes
        WHERE zone_id = ? AND serial > ? AND serial <= ?
        ORDER BY serial, id
        "#
    )
    .bind(zone_id)
    .bind(from_serial_i32)
    .bind(to_serial_i32)
    .fetch_all(pool)
    .await
    .map_err(|e| XfrError::DatabaseError(e.to_string()))?;

    let changes = rows
        .into_iter()
        .map(|row| ZoneChange {
            serial: row.serial as u32,
            operation: row.operation,
            record_name: row.record_name,
            record_type: row.record_type,
            record_value: row.record_value,
            record_ttl: row.record_ttl,
            record_priority: row.record_priority,
        })
        .collect();

    Ok(changes)
}
