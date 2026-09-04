use chrono::{DateTime, Utc};
use sqlx::FromRow;

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
    pub serial: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    /// The DNSSEC policy a signed zone signs under; owned by DNSSEC
    /// enable/disable, untouched by ordinary zone updates.
    pub dnssec_policy_id: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Whether the record is an apex NS row, whatever it points at.
fn is_apex_ns(record_type: &RecordType, name: &OwnerName) -> bool {
    *record_type == RecordType::NS && name.is_apex()
}

impl Zone {
    /// SOA RNAME (mailbox) in presentation form, e.g. `admin.example.com`.
    pub fn soa_mailbox(&self) -> Result<SoaMailbox, String> {
        SoaMailbox::from_email(&self.rname)
    }

    /// Whether the record is the apex NS this zone's `mname` names. One
    /// such row must exist for the zone to stay self-consistent.
    pub fn is_mname(&self, record_type: &RecordType, name: &OwnerName, value: &str) -> bool {
        is_apex_ns(record_type, name) && to_fqdn(value).eq_ignore_ascii_case(&to_fqdn(&self.mname))
    }

    /// TTL a synthesized apex NS must take to join the existing RRset rather
    /// than split it (RFC 2181, Section 5.2). `candidates` are scanned in
    /// priority order, falling back to the zone TTL.
    pub fn apex_ns_rrset_ttl<'a>(
        &self,
        candidates: impl IntoIterator<Item = (&'a RecordType, &'a OwnerName, i32)>,
    ) -> i32 {
        candidates
            .into_iter()
            .find(|(record_type, name, _)| is_apex_ns(record_type, name))
            .map_or(self.default_ttl, |(_, _, ttl)| ttl)
    }

    /// Whether the SOA metadata columns (everything but identity, serial, and
    /// the DNSSEC denial mode) differ from `other`'s.
    pub fn soa_metadata_differs(&self, other: &Zone) -> bool {
        self.mname != other.mname
            || self.rname != other.rname
            || self.default_ttl != other.default_ttl
            || self.refresh != other.refresh
            || self.retry != other.retry
            || self.expire != other.expire
            || self.minimum_ttl != other.minimum_ttl
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
