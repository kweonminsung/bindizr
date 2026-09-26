use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::{
    dns::name::OwnerName,
    model::{
        grant_pattern::{MATCH_ANY, matches_name, matches_types},
        record::RecordType,
    },
};

/// Grants one TSIG key rights over part of one zone, in the spirit of BIND's
/// `update-policy` and `allow-transfer`. Global keys bypass grants and hold no
/// rows here.
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
    /// Whether the grant permits updates. Transfers require an unrestricted
    /// name/type grant, regardless of this flag.
    pub can_write: bool,
    pub created_at: DateTime<Utc>,
}

impl TsigGrant {
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

/// A TSIG grant joined with the names of the key it belongs to and the zone
/// it covers.
#[derive(Debug, Clone)]
pub struct TsigGrantWithNames {
    pub grant: TsigGrant,
    pub tsig_key_name: String,
    pub zone_name: String,
}
