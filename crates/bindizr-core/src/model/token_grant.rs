use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::{
    dns::name::OwnerName,
    model::{
        grant_pattern::{MATCH_ANY, matches_name, matches_types},
        record::RecordType,
    },
};

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
    /// Whether the grant carries write rights as well as read. A read-only
    /// grant still makes the zone visible, narrowed the same way.
    pub can_write: bool,
    pub created_at: DateTime<Utc>,
}

impl TokenGrant {
    /// Whether this grant covers `record_type` at the relative owner name.
    pub fn matches(&self, name: &OwnerName, record_type: Option<&RecordType>) -> bool {
        matches_name(&self.record_name_pattern, name)
            && matches_types(&self.record_types, record_type)
    }

    /// Whether this grant covers every name and type in its zone.
    pub fn is_unrestricted(&self) -> bool {
        self.record_name_pattern == MATCH_ANY && self.record_types == MATCH_ANY
    }
}

/// A token grant joined with the names of the token it belongs to and the
/// zone it covers.
#[derive(Debug, Clone)]
pub struct TokenGrantWithNames {
    pub grant: TokenGrant,
    pub api_token_name: String,
    pub zone_name: String,
}
