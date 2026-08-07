use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Grants one API token record-plane rights over part of one zone, the HTTP
/// twin of [`super::zone_tsig_policy::ZoneTsigPolicy`]. Global tokens
/// (`ApiToken::is_global`) bypass policies entirely and hold no rows here.
///
/// `record_name_pattern` and `record_types` use the same syntax as TSIG
/// policies: `*`, `@`, `*.sub`, or an exact relative name; `*` or a
/// comma-separated list of record type mnemonics.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, FromRow)]
pub struct ZoneTokenPolicy {
    pub id: i32,
    pub zone_id: i32,
    pub api_token_id: i32,
    pub record_name_pattern: String,
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}
