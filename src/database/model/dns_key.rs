use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct DnsKey {
    pub id: i32,
    pub dns_id: i32,
    pub key_id: i32,
    pub created_at: DateTime<Utc>,
}
