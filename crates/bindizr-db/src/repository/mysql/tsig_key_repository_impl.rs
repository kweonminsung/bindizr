use async_trait::async_trait;
use sqlx::{MySql, Pool};

use crate::{error::DatabaseError, model::tsig_key::TsigKey, repository::TsigKeyRepository};

/// MySQL-backed implementation of `TsigKeyRepository`.
pub(crate) struct MySqlTsigKeyRepository {
    pool: Pool<MySql>,
}

impl MySqlTsigKeyRepository {
    pub(crate) fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TsigKeyRepository for MySqlTsigKeyRepository {
    async fn create(&self, mut key: TsigKey) -> Result<TsigKey, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO tsig_keys (name, algorithm, secret, is_global)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&key.name)
        .bind(key.algorithm.as_str())
        .bind(&key.secret)
        .bind(key.is_global)
        .execute(&mut *conn)
        .await?;

        key.id = result.last_insert_id() as i32;

        Ok(key)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<TsigKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let key = sqlx::query_as::<_, TsigKey>(
            "SELECT id, name, algorithm, secret, is_global, created_at FROM tsig_keys WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(key)
    }

    async fn list_all(&self) -> Result<Vec<TsigKey>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let keys = sqlx::query_as::<_, TsigKey>(
            "SELECT id, name, algorithm, secret, is_global, created_at FROM tsig_keys ORDER BY name",
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM tsig_keys WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
