use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::tsig_grant::TsigGrant,
    repository::{LockLevel, RepositoryTx, TsigGrantRepository, sql::lock_clause},
};

pub(crate) struct PostgresTsigGrantRepository {
    pool: Pool<Postgres>,
}

impl PostgresTsigGrantRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TsigGrantRepository for PostgresTsigGrantRepository {
    async fn create(&self, mut grant: TsigGrant) -> Result<TsigGrant, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO tsig_grants (zone_id, tsig_key_id, record_name_pattern, record_types)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(grant.zone_id)
        .bind(grant.tsig_key_id)
        .bind(&grant.record_name_pattern)
        .bind(&grant.record_types)
        .fetch_one(&mut *conn)
        .await?;

        grant.id = result.get::<i32, _>(0);

        Ok(grant)
    }

    async fn get(&self, id: i32) -> Result<Option<TsigGrant>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let grant = sqlx::query_as::<_, TsigGrant>(
            "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM tsig_grants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(grant)
    }

    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<TsigGrant>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let grants = sqlx::query_as::<_, TsigGrant>(
            "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM tsig_grants WHERE zone_id = $1 ORDER BY id",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(grants)
    }

    async fn list_by_zone_id_and_key_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<TsigGrant>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let grants = sqlx::query_as::<_, TsigGrant>(AssertSqlSafe(
            format!("SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM tsig_grants WHERE zone_id = $1 AND tsig_key_id = $2 ORDER BY id{}",
            lock_clause(lock_level),
        )))
        .bind(zone_id)
        .bind(tsig_key_id)
        .fetch_all(&mut **postgres_tx)
        .await?;

        Ok(grants)
    }

    async fn list_by_key_id(&self, tsig_key_id: i32) -> Result<Vec<TsigGrant>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let grants = sqlx::query_as::<_, TsigGrant>(
            "SELECT id, zone_id, tsig_key_id, record_name_pattern, record_types, created_at FROM tsig_grants WHERE tsig_key_id = $1 ORDER BY id",
        )
        .bind(tsig_key_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(grants)
    }

    async fn count_by_key_id(&self, tsig_key_id: i32) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tsig_grants WHERE tsig_key_id = $1")
                .bind(tsig_key_id)
                .fetch_one(&mut *conn)
                .await?;

        Ok(count as u64)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM tsig_grants WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
