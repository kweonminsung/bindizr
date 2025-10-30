use chrono::{DateTime, Utc};
use sqlx::FromRow;

// Structure for basic creation of SOA records and basic creation of NS records
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    pub name: String,                    // zone name (e.g.: "example.com")
    pub primary_ns: String,              // primary name server (e.g.: "ns1.example.com")
    pub primary_ns_ip: Option<String>,   // primary name server IP
    pub primary_ns_ipv6: Option<String>, // primary name server IPv6
    pub admin_email: String,             // admin email (e.g.: "admin.example.com")
    pub ttl: i32,                        // default TTL (seconds)
    pub serial: i32,                     // serial number (SOA record)
    pub refresh: i32,                    // refresh period (seconds)
    pub retry: i32,                      // retry period (seconds)
    pub expire: i32,                     // expire period (seconds)
    pub minimum_ttl: i32,                // minimum TTL (seconds)
    pub created_at: DateTime<Utc>,
}
