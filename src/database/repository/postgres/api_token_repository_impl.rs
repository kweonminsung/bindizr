use crate::database::{DatabasePool, model::api_token::ApiToken, repository::ApiTokenRepository};
use async_trait::async_trait;
use sqlx::Row;

pub struct PostgresApiTokenRepository {
    pool: DatabasePool,
}

impl PostgresApiTokenRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiTokenRepository for PostgresApiTokenRepository {
    async fn create(&self, mut token: ApiToken) -> Result<ApiToken, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let result = sqlx::query(
            r#"
            INSERT INTO api_tokens (token, description, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(&token.token)
        .bind(&token.description)
        .bind(&token.expires_at)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        token.id = result.get("id");
        Ok(token)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ApiToken>, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let token = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(token)
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let api_token = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens WHERE token = $1"
        )
        .bind(token)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(api_token)
    }

    async fn get_all(&self) -> Result<Vec<ApiToken>, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        let tokens = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC"
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(tokens)
    }

    async fn update(&self, token: ApiToken) -> Result<ApiToken, String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query(
            r#"
            UPDATE api_tokens 
            SET description = $1, expires_at = $2, last_used_at = $3
            WHERE id = $4
            "#,
        )
        .bind(&token.description)
        .bind(&token.expires_at)
        .bind(&token.last_used_at)
        .bind(token.id)
        .execute(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(token)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self
            .pool
            .get_connection()
            .await
            .map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM api_tokens WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
