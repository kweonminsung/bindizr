use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Dns {
    pub id: i32,
    pub name: String,   // unique name for the DNS
    pub host: String,   // DNS server host
    pub rndc_port: i32, // RNDC port
    pub created_at: DateTime<Utc>,
}
