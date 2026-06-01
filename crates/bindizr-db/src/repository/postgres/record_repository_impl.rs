use crate::error::DatabaseError;
use crate::{
    model::record::{Record, RecordType, RecordWithZone},
    repository::{RecordFilter, RecordRepository, RepositoryTx, RepositoryTxKind},
};
use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

pub struct PostgresRecordRepository {
    pool: Pool<Postgres>,
}

impl PostgresRecordRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        PostgresRecordRepository { pool }
    }
}

#[async_trait]
impl RecordRepository for PostgresRecordRepository {
    async fn create(&self, mut record: Record) -> Result<Record, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .fetch_one(&mut *conn)
        .await?;

        record.id = result.get::<i32, _>(0);

        Ok(record)
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut record: Record,
    ) -> Result<Record, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        let result = sqlx::query(
            r#"
            INSERT INTO records (name, record_type, value, ttl, priority, zone_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .fetch_one(&mut **postgres_tx)
        .await?;

        record.id = result.get::<i32, _>(0);
        Ok(record)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = $1")
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
            WHERE r.id = $1
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
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        let record = sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **postgres_tx)
            .await?;

        Ok(record)
    }

    async fn get_by_zone_id(&self, zone_id: i32) -> Result<Vec<Record>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let records =
            sqlx::query_as::<_, Record>("SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 ORDER BY name")
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
            WHERE r.zone_id = $1
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
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        let records = sqlx::query_as::<_, Record>(
            "SELECT id, name, record_type, value, ttl, priority, created_at, zone_id FROM records WHERE zone_id = $1 ORDER BY name FOR UPDATE",
        )
        .bind(zone_id)
        .fetch_all(&mut **postgres_tx)
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
        let value_filter = if record_type.is_name_like_value() {
            "AND ($5::TEXT IS NULL OR LOWER(value) = LOWER($6))"
        } else {
            "AND ($5::TEXT IS NULL OR value = $6)"
        };

        let query = format!(
            r#"
            SELECT id, name, record_type, value, ttl, priority, created_at, zone_id
            FROM records
            WHERE ($1::INT4 IS NULL OR zone_id = $2)
              AND LOWER(name) = LOWER($3)
              AND record_type = $4
              {value_filter}
              AND ($7 = 0 OR priority = $8 OR (priority IS NULL AND $9::INT4 IS NULL))
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
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };
        let value_filter = if record_type.is_name_like_value() {
            "AND ($5::TEXT IS NULL OR LOWER(value) = LOWER($6))"
        } else {
            "AND ($5::TEXT IS NULL OR value = $6)"
        };

        let query = format!(
            r#"
            SELECT id, name, record_type, value, ttl, priority, created_at, zone_id
            FROM records
            WHERE ($1::INT4 IS NULL OR zone_id = $2)
              AND LOWER(name) = LOWER($3)
              AND record_type = $4
              {value_filter}
              AND ($7 = 0 OR priority = $8 OR (priority IS NULL AND $9::INT4 IS NULL))
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
            .fetch_optional(&mut **postgres_tx)
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
        let search = like_pattern(filter.search.as_deref());

        let records = sqlx::query_as::<_, RecordWithZone>(
            r#"
            SELECT r.id, r.name, r.record_type, r.value, r.ttl, r.priority, r.created_at,
                   r.zone_id, z.name AS zone_name
            FROM records r
            INNER JOIN zones z ON z.id = r.zone_id
            WHERE ($1::TEXT IS NULL OR LOWER(z.name) = LOWER($2))
              AND (
                    $3::TEXT IS NULL
                    OR LOWER(r.name) = LOWER($4)
                    OR LOWER(CASE WHEN r.name = '@' THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) = LOWER($5)
              )
              AND ($6::TEXT IS NULL OR LOWER(r.record_type) = LOWER($7))
              AND ($8::TEXT IS NULL OR POSITION(LOWER($9) IN LOWER(r.value)) > 0 OR r.record_type = 'TXT')
              AND ($10::INT4 IS NULL OR r.ttl = $11)
              AND ($12::INT4 IS NULL OR r.ttl >= $13)
              AND ($14::INT4 IS NULL OR r.ttl <= $15)
              AND ($16::INT4 IS NULL OR r.priority = $17)
              AND ($18::INT4 IS NULL OR r.priority >= $19)
              AND ($20::INT4 IS NULL OR r.priority <= $21)
              AND (
                    $22::TEXT IS NULL
                    OR LOWER(z.name) LIKE LOWER($23)
                    OR LOWER(r.name) LIKE LOWER($24)
                    OR LOWER(CASE WHEN r.name = '@' THEN z.name || '.' ELSE r.name || '.' || z.name || '.' END) LIKE LOWER($25)
                    OR LOWER(r.record_type) LIKE LOWER($26)
                    OR LOWER(r.value) LIKE LOWER($27)
                    OR r.record_type = 'TXT'
              )
            ORDER BY r.name
            "#,
        )
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
        .fetch_all(&mut *conn)
        .await?;

        Ok(records)
    }

    async fn update(&self, record: Record) -> Result<Record, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE records
            SET name = $1, record_type = $2, value = $3, ttl = $4, priority = $5, zone_id = $6
            WHERE id = $7
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
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query(
            r#"
            UPDATE records
            SET name = $1, record_type = $2, value = $3, ttl = $4, priority = $5, zone_id = $6
            WHERE id = $7
            "#,
        )
        .bind(&record.name)
        .bind(record.record_type.to_string())
        .bind(&record.value)
        .bind(record.ttl)
        .bind(record.priority)
        .bind(record.zone_id)
        .bind(record.id)
        .execute(&mut **postgres_tx)
        .await?;

        Ok(record)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("DELETE FROM records WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query("DELETE FROM records WHERE id = $1")
            .bind(id)
            .execute(&mut **postgres_tx)
            .await?;
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
