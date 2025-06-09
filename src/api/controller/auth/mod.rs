pub mod middleware;

use crate::{
    database::{model::api_token::ApiToken, DatabasePool},
    log_error,
};
use chrono::{Duration, Utc};
use mysql::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};

pub struct AuthService;

impl AuthService {
    pub fn generate_token(
        pool: &DatabasePool,
        description: Option<&str>,
        expires_in_days: Option<i64>,
    ) -> Result<ApiToken, String> {
        // Generate random token (32 bytes)
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // SHA-256 hashing
        let mut hasher = Sha256::new();
        hasher.update(random_string);
        let token = hex::encode(hasher.finalize());

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

        let mut conn = pool.get_connection();
        match conn.exec_drop(
            r#"
            INSERT INTO api_tokens (token, description, expires_at)
            VALUES (?, ?, ?)
            "#,
            (
                &token,
                description,
                expires_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
            ),
        ) {
            Ok(_) => (),
            Err(e) => {
                log_error!("Failed to insert token: {}", e);
                return Err("Failed to create token".to_string());
            }
        };

        let token_id = conn.last_insert_id() as i32;

        Self::get_token_by_id(pool, token_id)
    }

    pub fn get_token_by_id(pool: &DatabasePool, token_id: i32) -> Result<ApiToken, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
            SELECT * FROM api_tokens WHERE id = ?
            "#,
            (token_id,),
            ApiToken::from_row,
        ) {
            Ok(tokens) => tokens,
            Err(e) => {
                log_error!("Failed to fetch token: {}", e);
                return Err("Failed to fetch token".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Token not found".to_string())
    }

    pub fn validate_token(pool: &DatabasePool, token_str: &str) -> Result<ApiToken, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
                SELECT * FROM api_tokens 
                WHERE token = ? 
                AND (expires_at IS NULL OR expires_at > NOW())
                "#,
            (token_str,),
            ApiToken::from_row,
        ) {
            Ok(tokens) => tokens,
            Err(e) => {
                log_error!("Failed to validate token: {}", e);
                return Err("Failed to validate token".to_string());
            }
        };

        let token = res
            .into_iter()
            .next()
            .ok_or_else(|| "Invalid or expired token".to_string())?;

        // Update last_used_at to current time
        match conn.exec_drop(
            r#"
            UPDATE api_tokens SET last_used_at = NOW() WHERE id = ?
            "#,
            (token.id,),
        ) {
            Ok(_) => (),
            Err(e) => {
                log_error!("Failed to update last_used_at: {}", e);
                return Err("Failed to update last_used_at".to_string());
            }
        }

        Ok(token)
    }

    pub fn list_tokens(pool: &DatabasePool) -> Result<Vec<ApiToken>, String> {
        let mut conn = pool.get_connection();

        match conn.exec_map(
            r#"
            SELECT * FROM api_tokens ORDER BY created_at DESC
            "#,
            (),
            ApiToken::from_row,
        ) {
            Ok(tokens) => Ok(tokens),
            Err(e) => {
                log_error!("Failed to list tokens: {}", e);
                Err("Failed to list tokens".to_string())
            }
        }
    }

    pub fn delete_token(pool: &DatabasePool, token_id: i32) -> Result<(), String> {
        let mut conn = pool.get_connection();

        // Check if the token exists
        Self::get_token_by_id(pool, token_id)?;

        match conn.exec_drop(
            r#"
            DELETE FROM api_tokens WHERE id = ?
            "#,
            (token_id,),
        ) {
            Ok(_) => (),
            Err(e) => {
                log_error!("Failed to delete token: {}", e);
                return Err("Failed to delete token".to_string());
            }
        }

        Ok(())
    }
}
