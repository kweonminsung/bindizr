use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::dns::name::{NameError, email_to_soa_mailbox};

/// Zone metadata used to generate the SOA and NS records.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    pub name: String,        // Zone name (e.g. "example.com")
    pub primary_ns: String,  // Primary name server (e.g. "ns1.example.com")
    pub admin_email: String, // Admin email (e.g. "admin.example.com")
    pub ttl: i32,            // Default TTL in seconds
    pub serial: i32,         // SOA serial number
    pub refresh: i32,        // SOA refresh period in seconds
    pub retry: i32,          // SOA retry period in seconds
    pub expire: i32,         // SOA expire period in seconds
    pub minimum_ttl: i32,    // SOA minimum TTL in seconds
    pub created_at: DateTime<Utc>,
}

impl Zone {
    /// SOA RNAME (mailbox) in presentation form, e.g. `admin.example.com`.
    pub fn soa_mailbox(&self) -> Result<String, NameError> {
        email_to_soa_mailbox(&self.admin_email)
    }

    /// SOA record RDATA: `<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>`.
    pub fn soa_rdata(&self) -> Result<String, NameError> {
        Ok(format!(
            "{} {} {} {} {} {} {}",
            self.primary_ns,
            self.soa_mailbox()?,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum_ttl
        ))
    }
}
