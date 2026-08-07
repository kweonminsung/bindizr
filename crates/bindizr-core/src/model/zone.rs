use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::dns::record::SoaMailbox;

/// Zone metadata used to generate the SOA and NS records.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    pub name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,         // Default TTL in seconds
    pub serial: i32,      // SOA serial number
    pub refresh: i32,     // SOA refresh period in seconds
    pub retry: i32,       // SOA retry period in seconds
    pub expire: i32,      // SOA expire period in seconds
    pub minimum_ttl: i32, // SOA minimum TTL in seconds
    pub created_at: DateTime<Utc>,
}

impl Zone {
    /// SOA RNAME (mailbox) in presentation form, e.g. `admin.example.com`.
    pub fn soa_mailbox(&self) -> Result<SoaMailbox, String> {
        SoaMailbox::from_email(&self.admin_email)
    }

    /// SOA record RDATA: `<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>`.
    pub fn soa_rdata(&self) -> Result<String, String> {
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
