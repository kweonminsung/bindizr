use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Grants one TSIG key nsupdate rights over part of one zone, in the spirit of
/// BIND's `update-policy`. Global keys bypass policies and hold no rows here.
///
/// `record_name_pattern` matches the owner name relative to the zone — `*`,
/// `@`, `*.sub`, or an exact relative name — and `record_types` is `*` or a
/// comma-separated list of type mnemonics.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct ZoneTsigPolicy {
    pub id: i32,
    pub zone_id: i32,
    pub tsig_key_id: i32,
    pub record_name_pattern: String,
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}
