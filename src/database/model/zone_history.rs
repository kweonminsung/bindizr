use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct ZoneHistory {
    pub id: i32,
    pub log: String,
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
}
