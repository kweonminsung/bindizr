use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct ZoneDnsConfig {
    pub id: i32,
    pub zone_id: i32,         // foreign key to zones table
    pub dns_instance_id: i32, // foreign key to dns_instances table
    pub dns_key_id: i32,      // foreign key to dns_keys table
    pub created_at: DateTime<Utc>,
}
