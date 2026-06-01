use crate::error::DatabaseError;
use crate::{
    model::record::{Record, RecordType, RecordWithZone},
    repository::{RecordRepository, RepositoryTx, RepositoryTxKind},
};
use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Sqlite};

pub struct SqliteRecordRepository {
    pool: Pool<Sqlite>,
}

impl SqliteRecordRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecordRepository for SqliteRecordRepository {
    async fn create(&self, mut record: Record) -> Result<Record, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(&mut *conn)
        .await?;

        record.id = result.last_insert_rowid() as i32;
        Ok(record)
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut record: Record,
    ) -> Result<Record, DatabaseError> {
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .execute(&mut **sqlite_tx)
        .await?;

        record.id = result.last_insert_rowid() as i32;
        Ok(record)
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut **sqlite_tx)
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = ? ORDER BY name",
        )
        .bind(zone_id)
        .fetch_all(&mut **sqlite_tx)
        .await?;

        Ok(records)
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
        let value_filter = if is_name_like_value(record_type) {
            "AND (? IS NULL OR LOWER(value) = LOWER(?))"
        } else {
            "AND (? IS NULL OR value = ?)"
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };
        let value_filter = if is_name_like_value(record_type) {
            "AND (? IS NULL OR LOWER(value) = LOWER(?))"
        } else {
            "AND (? IS NULL OR value = ?)"
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
            .fetch_optional(&mut **sqlite_tx)
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

    async fn update(&self, record: Record) -> Result<Record, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE records 
            SET name = ?, record_type = ?, value = ?, ttl = ?, priority = ?, zone_id = ?
            WHERE id = ?
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        sqlx::query(
            r#"
            UPDATE records 
            SET name = ?, record_type = ?, value = ?, ttl = ?, priority = ?, zone_id = ?
            WHERE id = ?
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .bind(record.id)
        .execute(&mut **sqlite_tx)
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(id)
            .execute(&mut **sqlite_tx)
            .await?;
        Ok(())
    }
}

fn is_name_like_value(record_type: &RecordType) -> bool {
    matches!(
        record_type,
        RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::MX
    )
}
