use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// An API authentication token and its metadata.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiToken {
    pub id: i32,
    pub token: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>, // None means the token never expires
    pub last_used_at: Option<DateTime<Utc>>, // None until the token is first used
}
