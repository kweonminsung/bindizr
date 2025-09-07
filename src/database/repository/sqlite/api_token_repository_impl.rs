use crate::database::{model::api_token::ApiToken, repository::ApiTokenRepository};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

pub struct SqliteApiTokenRepository {
    pool: Pool<Sqlite>,
}

impl SqliteApiTokenRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApiTokenRepository for SqliteApiTokenRepository {
    async fn create(&self, mut token: ApiToken) -> Result<ApiToken, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

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
        .await
        .map_err(|e| e.to_string())?;

        token.id = result.last_insert_rowid() as i32;
        Ok(token)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<ApiToken>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let token = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(token)
    }

    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let api_token = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens WHERE token = ?"
        )
        .bind(token)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(api_token)
    }

    async fn get_all(&self) -> Result<Vec<ApiToken>, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        let tokens = sqlx::query_as::<_, ApiToken>(
            "SELECT id, token, description, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC"
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| e.to_string())?;

        Ok(tokens)
    }

    async fn update(&self, token: ApiToken) -> Result<ApiToken, String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

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
        .await
        .map_err(|e| e.to_string())?;

        Ok(token)
    }

    async fn delete(&self, id: i32) -> Result<(), String> {
        let mut conn = self.pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM api_tokens WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
