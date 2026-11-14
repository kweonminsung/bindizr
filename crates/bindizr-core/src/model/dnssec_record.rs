use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;
use utoipa::ToSchema;

use crate::dns::Ttl;
use crate::dns::name::{OwnerName, ZoneName};
use crate::dns::record::Rdata;
use crate::model::zone::ZoneId;

id_newtype!(
    /// The id of a derived DNSSEC record row.
    DnssecRecordId
);

/// A signer-generated record in the zone's DNSSEC view.
/// The record API exposes these read-only through its `signed` flag.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct DnssecRecord {
    pub id: DnssecRecordId,
    pub zone_id: ZoneId,
    pub name: OwnerName,
    #[sqlx(try_from = "i32")]
    pub record_type: DnssecRecordType,
    /// RRSIG rows: the covered record type; NULL otherwise.
    pub covered_record_type: Option<i32>,
    pub ttl: Ttl,
    pub rdata: Rdata,
    /// RRSIG rows: signature expiration, driving the re-signing schedule.
    pub expires_at: Option<DateTime<Utc>>,
    /// RRSIG rows: digest of the signed record set content, allowing a still-valid
    /// signature to be reused when the record set has not changed.
    pub record_set_digest: Option<String>,
}

/// What makes two derived records the same: owner, type, TTL, and rdata,
/// every byte of which a signature covers. The row id and the RRSIG
/// metadata, which change on re-signing, are left out.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnssecRecordKey {
    name: OwnerName,
    record_type: DnssecRecordType,
    ttl: Ttl,
    rdata: Rdata,
}

impl DnssecRecord {
    /// Return this record's identity for set matching.
    pub fn match_key(&self) -> DnssecRecordKey {
        DnssecRecordKey {
            name: self.name.clone(),
            record_type: self.record_type,
            ttl: self.ttl,
            rdata: self.rdata.clone(),
        }
    }
}

/// A derived record joined with its zone name, as the signed records listing
/// returns it.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct DnssecRecordWithZone {
    pub name: OwnerName,
    #[sqlx(try_from = "i32")]
    pub record_type: DnssecRecordType,
    pub ttl: Ttl,
    pub rdata: Rdata,
    pub zone_id: ZoneId,
    pub zone_name: ZoneName,
}

/// A derived record type bindizr does not generate, by number or mnemonic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseDnssecRecordTypeError {
    #[error("unknown derived record type {value}")]
    Number { value: i32 },
    #[error("unknown derived record type '{value}'")]
    Name { value: String },
}

/// The record types the signer derives; rows store the wire record type number
/// (RFC 4034).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "UPPERCASE")]
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
    /// Return the DNS wire type number for this derived record type.
    pub fn wire_type(self) -> u16 {
        match self {
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Dnskey => 48,
            Self::Nsec3 => 50,
            Self::Nsec3param => 51,
            Self::Cds => 59,
            Self::Cdnskey => 60,
        }
    }

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rrsig => "RRSIG",
            Self::Nsec => "NSEC",
            Self::Dnskey => "DNSKEY",
            Self::Nsec3 => "NSEC3",
            Self::Nsec3param => "NSEC3PARAM",
            Self::Cds => "CDS",
            Self::Cdnskey => "CDNSKEY",
        }
    }
}

impl fmt::Display for DnssecRecordType {
    /// Write the DNSSEC record type in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DnssecRecordType {
    type Err = ParseDnssecRecordTypeError;

    /// Parse a DNSSEC record type from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "RRSIG" => Ok(Self::Rrsig),
            "NSEC" => Ok(Self::Nsec),
            "DNSKEY" => Ok(Self::Dnskey),
            "NSEC3" => Ok(Self::Nsec3),
            "NSEC3PARAM" => Ok(Self::Nsec3param),
            "CDS" => Ok(Self::Cds),
            "CDNSKEY" => Ok(Self::Cdnskey),
            _ => Err(ParseDnssecRecordTypeError::Name {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<i32> for DnssecRecordType {
    type Error = ParseDnssecRecordTypeError;

    /// Validate and convert the stored value into a DNSSEC record type.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            46 => Ok(Self::Rrsig),
            47 => Ok(Self::Nsec),
            48 => Ok(Self::Dnskey),
            50 => Ok(Self::Nsec3),
            51 => Ok(Self::Nsec3param),
            59 => Ok(Self::Cds),
            60 => Ok(Self::Cdnskey),
            _ => Err(ParseDnssecRecordTypeError::Number { value }),
        }
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for DnssecRecordType
where
    i32: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <i32 as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <i32 as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for DnssecRecordType
where
    i32: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        i32::from(self.wire_type()).encode_by_ref(buffer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `DnssecRecordType` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn dnssec_record_type_spells_itself_once() {
        for value in [
            DnssecRecordType::Rrsig,
            DnssecRecordType::Nsec,
            DnssecRecordType::Dnskey,
            DnssecRecordType::Nsec3,
            DnssecRecordType::Nsec3param,
            DnssecRecordType::Cds,
            DnssecRecordType::Cdnskey,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<DnssecRecordType>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<DnssecRecordType>().unwrap(), value);
        }
    }
}
