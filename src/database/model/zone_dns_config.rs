use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct ZoneDnsConfig {
    pub id: i32,
    pub zone_id: i32, // foreign key to zones table
    pub dns_id: i32,  // foreign key to dnss table
    pub key_id: i32,  // foreign key to keys table
    pub created_at: DateTime<Utc>,
}
