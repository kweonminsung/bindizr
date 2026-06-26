use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::dns::name::{NameError, email_to_soa_mailbox};

// Structure for basic creation of SOA records and basic creation of NS records
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    pub name: String,        // zone name (e.g.: "example.com")
    pub primary_ns: String,  // primary name server (e.g.: "ns1.example.com")
    pub admin_email: String, // admin email (e.g.: "admin.example.com")
    pub ttl: i32,            // default TTL (seconds)
    pub serial: i32,         // serial number (SOA record)
    pub refresh: i32,        // refresh period (seconds)
    pub retry: i32,          // retry period (seconds)
    pub expire: i32,         // expire period (seconds)
    pub minimum_ttl: i32,    // minimum TTL (seconds)
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
