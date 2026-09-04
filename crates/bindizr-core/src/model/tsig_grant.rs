use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Grants one TSIG key nsupdate rights over part of one zone, in the spirit of
/// BIND's `update-policy`. Global keys bypass grants and hold no rows here.
///
/// `record_name_pattern` matches the owner name relative to the zone — `*`,
/// `@`, `*.sub`, or an exact relative name — and `record_types` is `*` or a
/// comma-separated list of type mnemonics.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct TsigGrant {
    pub id: i32,
    pub zone_id: i32,
    pub tsig_key_id: i32,
    pub record_name_pattern: String,
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

/// A TSIG grant joined with the names of the key it belongs to and the zone
/// it covers.
#[derive(Debug, Clone)]
pub struct TsigGrantWithNames {
    pub grant: TsigGrant,
    pub tsig_key_name: String,
    pub zone_name: String,
}
