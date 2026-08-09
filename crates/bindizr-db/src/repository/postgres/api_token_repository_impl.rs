use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

use crate::{error::DatabaseError, model::api_token::ApiToken, repository::ApiTokenRepository};

/// PostgreSQL-backed implementation of `ApiTokenRepository`.
pub struct PostgresApiTokenRepository {
    pool: Pool<Postgres>,
}

impl PostgresApiTokenRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiTokenRepository for PostgresApiTokenRepository {
    async fn create(&self, mut token: ApiToken) -> Result<ApiToken, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO api_tokens (name, token, description, is_global, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        "#,
        )
        .bind(&token.name)
        .bind(&token.token)
        .bind(&token.description)
        .bind(token.is_global)
        .bind(token.expires_at)
        .fetch_one(&mut *conn)
        .await?;

        token.id = result.get::<i32, _>(0);

        Ok(token)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let row = sqlx::query_as::<_, ApiToken>(
            "SELECT id, name, token, description, is_global, expires_at, created_at, last_used_at FROM api_tokens WHERE name = $1"
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await
        ?;

        Ok(row)
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let row = sqlx::query_as::<_, ApiToken>(
            "SELECT id, name, token, description, is_global, expires_at, created_at, last_used_at FROM api_tokens WHERE token = $1"
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
            "SELECT id, name, token, description, is_global, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC"
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
            SET description = $1, expires_at = $2, last_used_at = $3
            WHERE id = $4
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

        sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
