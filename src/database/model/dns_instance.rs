use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct DnsInstance {
   pub id: i32,
   pub name: Option<String>,    // optional name for the DNS instance
   pub host: String,            // DNS server host
   pub rndc_port: i32,          // RNDC port
   pub rndc_key_id: i32,        // foreign key to dns_keys table
   pub created_at: DateTime<Utc>,
}
