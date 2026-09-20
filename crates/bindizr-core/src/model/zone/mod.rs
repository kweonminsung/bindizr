use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::dns::{
    name::ZoneName,
    record::{Rdata, SoaMailbox, SoaRecordValue},
};

/// Zone metadata used to generate the SOA and NS records.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Zone {
    pub id: i32,
    #[sqlx(try_from = "String")]
    pub name: ZoneName,
    pub mname: String,
    /// Stored as the admin email (`admin@example.com`); rendered to the SOA
    /// RNAME mailbox form only when served. `ZoneVersion.rname` differs.
    pub rname: String,
    pub default_ttl: i32,
    pub serial: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    /// The DNSSEC policy a signed zone signs under; owned by DNSSEC
    /// enable/disable, untouched by ordinary zone updates.
    pub dnssec_policy_id: Option<i32>,
    /// The parent zone's nameservers asked for the zone's DS, as
    /// comma-separated `host[:port]`; `None` means unconfigured. DNSSEC-owned
    /// like `dnssec_policy_id`.
    pub parent_ns_addrs: Option<String>,
    /// Whether the DNS plane knows the zone. A disabled one stays editable but
    /// leaves the catalog and answers no transfer, so secondaries drop it.
    pub enabled: bool,
    /// Free-text note for operators; bindizr never reads it.
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Zone {
    /// SOA RNAME (mailbox) in presentation form, e.g. `admin.example.com`.
    pub fn soa_mailbox(&self) -> Result<SoaMailbox, String> {
        SoaMailbox::from_email(&self.rname)
    }

    /// Whether the SOA metadata differs from `other`, excluding the serial.
    pub fn soa_metadata_differs(&self, other: &Zone) -> bool {
        self.mname != other.mname
            || self.rname != other.rname
            || self.default_ttl != other.default_ttl
            || self.refresh != other.refresh
            || self.retry != other.retry
            || self.expire != other.expire
            || self.minimum_ttl != other.minimum_ttl
    }

    /// This zone's wire-format SOA RDATA at `serial`; the SOA is synthesized
    /// from zone columns, never stored as a record row.
    pub(crate) fn soa_rdata(&self, serial: u32) -> Result<Rdata, String> {
        let rname = self.soa_mailbox()?;
        SoaRecordValue {
            mname: &self.mname,
            rname: rname.as_str(),
            serial,
            refresh: self.refresh as u32,
            retry: self.retry as u32,
            expire: self.expire as u32,
            minimum: self.minimum_ttl as u32,
        }
        .to_rdata()
    }

    /// SOA RDATA in presentation form:
    /// `<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>`.
    pub fn soa_presentation_rdata(&self) -> Result<String, String> {
        Ok(format!(
            "{} {} {} {} {} {} {}",
            self.mname,
            self.soa_mailbox()?,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum_ttl
        ))
    }
}
