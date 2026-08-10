use sqlx::FromRow;

use crate::dns::name::OwnerName;

/// A single record add/delete change within a zone, used for IXFR.
#[derive(Debug, Clone, FromRow)]
pub struct ZoneChange {
    pub id: i32,
    pub zone_id: i32,
    pub serial: i32,
    pub operation: String, // OP_ADD or OP_DEL
    #[sqlx(try_from = "String")]
    pub record_name: OwnerName,
    pub record_type: String,
    pub record_value: String,
    pub record_ttl: i32,
    pub record_priority: Option<i32>,
}

impl ZoneChange {
    /// Stored `operation` value for a record addition.
    pub const OP_ADD: &'static str = "ADD";
    /// Stored `operation` value for a record deletion.
    pub const OP_DEL: &'static str = "DEL";
}
