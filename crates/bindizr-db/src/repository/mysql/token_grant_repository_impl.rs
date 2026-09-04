use async_trait::async_trait;
use sqlx::{AssertSqlSafe, MySql, Pool};

use crate::{
    error::DatabaseError,
    model::token_grant::TokenGrant,
    repository::{LockLevel, RepositoryTx, TokenGrantRepository, sql::lock_clause},
};

pub(crate) struct MySqlTokenGrantRepository {
    pool: Pool<MySql>,
}

impl MySqlTokenGrantRepository {
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenGrantRepository for MySqlTokenGrantRepository {
    async fn create(&self, mut grant: TokenGrant) -> Result<TokenGrant, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO token_grants (zone_id, api_token_id, record_name_pattern, record_types)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(grant.zone_id)
        .bind(grant.api_token_id)
        .bind(&grant.record_name_pattern)
        .bind(&grant.record_types)
        .execute(&mut *conn)
        .await?;

        grant.id = result.last_insert_id() as i32;

        Ok(grant)
    }

    async fn get(&self, id: i32) -> Result<Option<TokenGrant>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let grant = sqlx::query_as::<_, TokenGrant>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM token_grants WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(grant)
    }

    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<TokenGrant>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let grants = sqlx::query_as::<_, TokenGrant>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM token_grants WHERE zone_id = ? ORDER BY id",
        )
        .bind(zone_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(grants)
    }

    async fn list_by_zone_id_and_token_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<TokenGrant>, DatabaseError> {
        let mysql_tx = tx.as_mysql()?;

        let grants = sqlx::query_as::<_, TokenGrant>(AssertSqlSafe(
            format!("SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM token_grants WHERE zone_id = ? AND api_token_id = ? ORDER BY id{}",
            lock_clause(lock_level),
        )))
        .bind(zone_id)
        .bind(api_token_id)
        .fetch_all(&mut **mysql_tx)
        .await?;

        Ok(grants)
    }

    async fn list_by_token_id(&self, api_token_id: i32) -> Result<Vec<TokenGrant>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let grants = sqlx::query_as::<_, TokenGrant>(
            "SELECT id, zone_id, api_token_id, record_name_pattern, record_types, created_at FROM token_grants WHERE api_token_id = ? ORDER BY id",
        )
        .bind(api_token_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(grants)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM token_grants WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
