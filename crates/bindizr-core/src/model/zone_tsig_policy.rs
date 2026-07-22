use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Grants one TSIG key nsupdate rights over part of one zone, in the spirit of
/// BIND's `update-policy`. A zone may hold any number of policies (multiple
/// keys) and a key may appear in policies of any number of zones. Global keys
/// (`TsigKey::is_global`) bypass policies entirely and hold no rows here.
///
/// `record_name_pattern` is matched against the record's owner name relative to
/// the zone: `*` (any name), `*.sub` (sub and everything under it), an exact
/// relative name, or `@` (zone apex). `record_types` is `*` or a comma-separated
/// list of record type mnemonics (e.g. `A,AAAA,TXT`).
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, FromRow)]
pub struct ZoneTsigPolicy {
    pub id: i32,
    pub zone_id: i32,
    pub tsig_key_id: i32,
    pub record_name_pattern: String,
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}
