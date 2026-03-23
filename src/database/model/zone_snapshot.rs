use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ZoneSnapshot {
    pub id: i32,
    pub zone_id: i32,
    pub serial: i32,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    pub created_at: DateTime<Utc>,
}
