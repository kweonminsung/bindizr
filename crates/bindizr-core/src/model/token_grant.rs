use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::{
    dns::name::OwnerName,
    model::{
        api_token::TokenId,
        grant_pattern::{MATCH_ANY, matches_name, matches_types},
        record::RecordType,
        zone::ZoneId,
    },
};

id_newtype!(
    /// The id of a token grant row.
    TokenGrantId
);

/// An API token's record-plane rights within one zone, using [`super::tsig_grant::TsigGrant`] syntax.
/// Global tokens bypass grants and hold no rows here.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct TokenGrant {
    pub id: TokenGrantId,
    pub zone_id: ZoneId,
    pub api_token_id: TokenId,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGrantWithNames {
    pub grant: TokenGrant,
    pub api_token_name: String,
    pub zone_name: String,
}
