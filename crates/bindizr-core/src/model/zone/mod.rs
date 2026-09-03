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
    pub serial: i32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
    /// Denial-of-existence mode when the zone is signed; owned by DNSSEC
    /// enable/disable, untouched by ordinary zone updates.
    #[sqlx(try_from = "String")]
    pub dnssec_denial: DnssecDenial,
    /// Timing overrides owned by the DNSSEC timing endpoint; `None`
    /// inherits the global config.
    pub dnssec_signature_validity_days: Option<i32>,
    pub dnssec_signature_refresh_days: Option<i32>,
    pub dnssec_zsk_lifetime_days: Option<i32>,
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

    /// Effective signature validity window: the zone override or `default`.
    pub fn signature_validity_days(&self, default: u32) -> u32 {
        self.dnssec_signature_validity_days
            .map_or(default, |days| days.max(0) as u32)
    }

    /// Effective re-sign threshold: the zone override or `default`.
    pub fn signature_refresh_days(&self, default: u32) -> u32 {
        self.dnssec_signature_refresh_days
            .map_or(default, |days| days.max(0) as u32)
    }

    /// Effective re-sign threshold clamped into `[1, validity - 1]`, as
    /// signing and the re-sign scan apply it.
    pub fn clamped_signature_refresh_days(
        &self,
        default_refresh: u32,
        default_validity: u32,
    ) -> u32 {
        self.signature_refresh_days(default_refresh)
            .min(
                self.signature_validity_days(default_validity)
                    .saturating_sub(1),
            )
            .max(1)
    }

    /// Effective ZSK lifetime (0 disables auto-roll): the zone override or
    /// `default`.
    pub fn zsk_lifetime_days(&self, default: u32) -> u32 {
        self.dnssec_zsk_lifetime_days
            .map_or(default, |days| days.max(0) as u32)
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
