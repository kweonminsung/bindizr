use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiToken {
    pub id: i32,
    pub token: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}
