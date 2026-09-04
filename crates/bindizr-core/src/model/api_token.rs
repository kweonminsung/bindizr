use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// An API authentication token and its metadata.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct ApiToken {
    pub id: i32,
    /// Unique human-facing identifier; CLI and API reference tokens by name.
    pub name: String,
    pub token: String,
    pub description: Option<String>,
    /// Global tokens may manage every zone and the zone plane; scoped tokens
    /// are limited to their `token_grants` grants. Fixed at creation.
    pub is_global: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>, // None means the token never expires
    pub last_used_at: Option<DateTime<Utc>>, // None until the token is first used
}
