use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::model::role::RoleId;

id_newtype!(
    /// The id of an API token row.
    TokenId
);

/// An API authentication token and its metadata.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct ApiToken {
    pub id: TokenId,
    /// Unique human-facing identifier; CLI and API reference tokens by name.
    pub name: String,
    pub token: String,
    pub description: Option<String>,
    /// The role whose grants decide what the token may do; the token itself carries no rights.
    pub role_id: RoleId,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>, // None means the token never expires
    pub last_used_at: Option<DateTime<Utc>>, // None until the token is first used
}
