use async_trait::async_trait;
use sqlx::{MySql, Pool};

use crate::{error::DatabaseError, model::api_token::ApiToken, repository::ApiTokenRepository};

pub struct MySqlApiTokenRepository {
    pool: Pool<MySql>,
}

impl MySqlApiTokenRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiTokenRepository for MySqlApiTokenRepository {
    async fn create(&self, mut token: ApiToken) -> Result<ApiToken, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO api_tokens (token, description, expires_at)
            VALUES (?, ?, ?)
        "#,
        )
        .bind(&token.token)
        .bind(&token.description)
        .bind(token.expires_at)
        .execute(&mut *conn)
        .await?;

        token.id = result.last_insert_id() as i32;

        Ok(token)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ApiToken>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let row = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        ?;

        Ok(row)
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let row = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens WHERE token = ?"
        )
        .bind(token)
        .fetch_optional(&mut *conn)
        .await
        ?;

        Ok(row)
    }

    async fn get_all(&self) -> Result<Vec<ApiToken>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let rows = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC"
        )
        .fetch_all(&mut *conn)
        .await
        ?;

        Ok(rows)
    }

    async fn update(&self, token: ApiToken) -> Result<ApiToken, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE api_tokens 
            SET description = ?, expires_at = ?, last_used_at = ?
            WHERE id = ?
        "#,
        )
        .bind(&token.description)
        .bind(token.expires_at)
        .bind(token.last_used_at)
        .bind(token.id)
        .execute(&mut *conn)
        .await?;

        Ok(token)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM api_tokens WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
