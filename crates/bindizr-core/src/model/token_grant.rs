use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Grants one API token record-plane rights over part of one zone, the HTTP
/// twin of [`super::tsig_grant::TsigGrant`]. Global tokens
/// (`ApiToken::is_global`) bypass grants entirely and hold no rows here.
///
/// `record_name_pattern` and `record_types` take the same syntax as a TSIG
/// grant's.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct TokenGrant {
    pub id: i32,
    pub zone_id: i32,
    pub api_token_id: i32,
    pub record_name_pattern: String,
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

/// A token grant joined with the names of the token it belongs to and the
/// zone it covers.
#[derive(Debug, Clone)]
pub struct TokenGrantWithNames {
    pub grant: TokenGrant,
    pub api_token_name: String,
    pub zone_name: String,
}
