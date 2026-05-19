use crate::database::error::DatabaseError;
use crate::database::{
    model::record::{Record, RecordType},
    repository::{RecordRepository, RepositoryTx, RepositoryTxKind},
};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

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
        let value_filter = if is_name_like_value(record_type) {
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

        let record = sqlx::query_as::<_, Record>(&query)
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
        let value_filter = if is_name_like_value(record_type) {
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

        let record = sqlx::query_as::<_, Record>(&query)
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

fn is_name_like_value(record_type: &RecordType) -> bool {
    matches!(
        record_type,
        RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::MX
    )
}
