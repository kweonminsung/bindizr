use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// Point-in-time version of a zone's SOA fields at a given serial.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ZoneVersion {
    pub id: i32,
    pub zone_id: i32,
    pub serial: i32,
    pub mname: String,
    /// Stored in SOA mailbox encoded form, unlike `Zone.rname` which holds the
    /// admin email.
    pub rname: String,
    pub default_ttl: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    pub created_at: DateTime<Utc>,
}
