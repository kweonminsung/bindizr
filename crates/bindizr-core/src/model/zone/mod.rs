use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// How a signed zone proves nonexistence (denial of existence).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DnssecDenial {
    /// Plain NSEC chain over the zone's names.
    Nsec,
    /// Hashed NSEC3 chain (RFC 5155), with the RFC 9276 parameters.
    Nsec3,
}

impl DnssecDenial {
    /// Storage and presentation name.
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecDenial::Nsec => "nsec",
            DnssecDenial::Nsec3 => "nsec3",
        }
    }
}

impl std::fmt::Display for DnssecDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for DnssecDenial {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "nsec" => Ok(DnssecDenial::Nsec),
            "nsec3" => Ok(DnssecDenial::Nsec3),
            _ => Err(format!(
                "unsupported denial mode '{}' (supported: nsec, nsec3)",
                s
            )),
        }
    }
}

impl TryFrom<String> for DnssecDenial {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

use crate::{
    dns::{
        name::{OwnerName, ZoneName, to_fqdn},
        record::{Rdata, SoaMailbox, SoaRecordValue},
    },
    model::record::{Record, RecordType},
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
    pub serial: i32,      // SOA serial number
    pub refresh: i32,     // SOA refresh period in seconds
    pub retry: i32,       // SOA retry period in seconds
    pub expire: i32,      // SOA expire period in seconds
    pub minimum_ttl: i32, // SOA minimum TTL in seconds
    /// Denial-of-existence mode when the zone is signed; owned by DNSSEC
    /// enable/disable, untouched by ordinary zone updates.
    #[sqlx(try_from = "String")]
    pub dnssec_denial: DnssecDenial,
    pub created_at: DateTime<Utc>,
}

impl Zone {
    /// SOA RNAME (mailbox) in presentation form, e.g. `admin.example.com`.
    pub fn soa_mailbox(&self) -> Result<SoaMailbox, String> {
        SoaMailbox::from_email(&self.rname)
    }

    /// Whether the record is an apex NS row, whatever it points at.
    pub fn is_apex_ns(&self, record_type: &RecordType, name: &OwnerName) -> bool {
        *record_type == RecordType::NS && name.is_apex()
    }

    /// Whether the record is the apex NS this zone's `mname` names. One
    /// such row must exist for the zone to stay self-consistent.
    pub fn is_mname(&self, record_type: &RecordType, name: &OwnerName, value: &str) -> bool {
        self.is_apex_ns(record_type, name)
            && to_fqdn(value).eq_ignore_ascii_case(&to_fqdn(&self.mname))
    }

    /// The apex NS row that satisfies [`Self::is_mname`].
    pub fn mname_record(&self, ttl: i32) -> Record {
        Record {
            id: 0,
            name: OwnerName::apex(),
            record_type: RecordType::NS,
            value: self.mname.clone(),
            ttl,
            priority: None,
            zone_id: self.id,
            created_at: Utc::now(),
        }
    }

    /// This zone's wire-format SOA RDATA at `serial`; the SOA is synthesized
    /// from zone columns, never stored as a record row.
    pub fn soa_rdata(&self, serial: u32) -> Result<Rdata, String> {
        let rname = SoaMailbox::from_email(&self.rname)?;
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

#[cfg(test)]
mod tests;
