use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::{
    dns::{
        name::{OwnerName, ZoneName, to_fqdn},
        record::SoaMailbox,
    },
    model::record::{Record, RecordType},
};

/// Zone metadata used to generate the SOA and NS records.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    #[sqlx(try_from = "String")]
    pub name: ZoneName,
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

    /// Whether the record is an apex NS row, whatever it points at.
    pub fn is_apex_ns(&self, record_type: &RecordType, name: &OwnerName) -> bool {
        *record_type == RecordType::NS && name.is_apex()
    }

    /// Whether the record is the apex NS this zone's `primary_ns` names. One
    /// such row must exist for the zone to stay self-consistent.
    pub fn is_primary_ns(&self, record_type: &RecordType, name: &OwnerName, value: &str) -> bool {
        self.is_apex_ns(record_type, name)
            && to_fqdn(value).eq_ignore_ascii_case(&to_fqdn(&self.primary_ns))
    }

    /// The apex NS row that satisfies [`Self::is_primary_ns`].
    pub fn primary_ns_record(&self, ttl: i32) -> Record {
        Record {
            id: 0,
            name: OwnerName::apex(),
            record_type: RecordType::NS,
            value: self.primary_ns.clone(),
            ttl,
            priority: None,
            zone_id: self.id,
            created_at: Utc::now(),
        }
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

#[cfg(test)]
mod tests;
