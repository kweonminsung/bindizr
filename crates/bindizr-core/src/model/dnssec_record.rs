use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::dns::{
    name::{OwnerName, ZoneName},
    record::Rdata,
};

/// One record of a zone's derived DNSSEC plane (the signed view): the DNSKEY,
/// NSEC, and RRSIG rows the signer generates. These are system-owned and never
/// user data — the record API cannot create or modify them, and lists them
/// only behind its `signed` flag.
#[derive(Debug, Clone, FromRow)]
pub struct DnssecRecord {
    pub id: i32,
    pub zone_id: i32,
    #[sqlx(try_from = "String")]
    pub name: OwnerName,
    #[sqlx(try_from = "i32")]
    pub record_type: DnssecRecordType,
    /// RRSIG rows: the covered RR type; NULL otherwise.
    pub covered_record_type: Option<i32>,
    pub ttl: i32,
    pub rdata: Rdata,
    /// RRSIG rows: signature expiration, driving the re-signing schedule.
    pub expires_at: Option<DateTime<Utc>>,
    /// RRSIG rows: digest of the signed RRset content, allowing a still-valid
    /// signature to be reused when the RRset has not changed.
    pub rrset_digest: Option<String>,
}

/// A derived record joined with its zone name, as the signed records listing
/// returns it.
#[derive(Debug, Clone, FromRow)]
pub struct DnssecRecordWithZone {
    #[sqlx(try_from = "String")]
    pub name: OwnerName,
    #[sqlx(try_from = "i32")]
    pub record_type: DnssecRecordType,
    pub ttl: i32,
    pub rdata: Rdata,
    pub zone_id: i32,
    #[sqlx(try_from = "String")]
    pub zone_name: ZoneName,
}

/// The record types the signer derives; rows store the wire RR type number
/// (RFC 4034).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnssecRecordType {
    Rrsig,
    Nsec,
    Dnskey,
    Nsec3,
    Nsec3param,
    Cds,
    Cdnskey,
}

impl DnssecRecordType {
    pub fn wire_type(self) -> u16 {
        match self {
            DnssecRecordType::Rrsig => 46,
            DnssecRecordType::Nsec => 47,
            DnssecRecordType::Dnskey => 48,
            DnssecRecordType::Nsec3 => 50,
            DnssecRecordType::Nsec3param => 51,
            DnssecRecordType::Cds => 59,
            DnssecRecordType::Cdnskey => 60,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DnssecRecordType::Rrsig => "RRSIG",
            DnssecRecordType::Nsec => "NSEC",
            DnssecRecordType::Dnskey => "DNSKEY",
            DnssecRecordType::Nsec3 => "NSEC3",
            DnssecRecordType::Nsec3param => "NSEC3PARAM",
            DnssecRecordType::Cds => "CDS",
            DnssecRecordType::Cdnskey => "CDNSKEY",
        }
    }
}

impl std::fmt::Display for DnssecRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<i32> for DnssecRecordType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            46 => Ok(DnssecRecordType::Rrsig),
            47 => Ok(DnssecRecordType::Nsec),
            48 => Ok(DnssecRecordType::Dnskey),
            50 => Ok(DnssecRecordType::Nsec3),
            51 => Ok(DnssecRecordType::Nsec3param),
            59 => Ok(DnssecRecordType::Cds),
            60 => Ok(DnssecRecordType::Cdnskey),
            other => Err(format!("unknown derived record type {}", other)),
        }
    }
}

impl std::str::FromStr for DnssecRecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RRSIG" => Ok(DnssecRecordType::Rrsig),
            "NSEC" => Ok(DnssecRecordType::Nsec),
            "DNSKEY" => Ok(DnssecRecordType::Dnskey),
            "NSEC3" => Ok(DnssecRecordType::Nsec3),
            "NSEC3PARAM" => Ok(DnssecRecordType::Nsec3param),
            "CDS" => Ok(DnssecRecordType::Cds),
            "CDNSKEY" => Ok(DnssecRecordType::Cdnskey),
            other => Err(format!("unknown derived record type '{}'", other)),
        }
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for DnssecRecordType
where
    i32: sqlx::Type<DB>,
{
    fn type_info() -> DB::TypeInfo {
        <i32 as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i32 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for DnssecRecordType
where
    i32: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        (self.wire_type() as i32).encode_by_ref(buf)
    }
}
