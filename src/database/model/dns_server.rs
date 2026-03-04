use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct DnsServer {
    pub id: i32,
    pub ip_address: String,
    pub port: i32,
    pub created_at: DateTime<Utc>,
}
