use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use domain::base::iana::Rtype;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{ObjectBuilder, Schema, Type};

use crate::dns::name::{OwnerName, ZoneName};
use crate::dns::record::{
    ARecordValue, AaaaRecordValue, CaaRecordValue, CnameRecordValue, DEFAULT_PRIORITY,
    DnameRecordValue, DsRecordValue, EncodeRdataError, MxRecordValue, NaptrRecordValue,
    NsRecordValue, ParseRecordValueError, PtrRecordValue, Rdata, SrvRecordValue, SshfpRecordValue,
    TlsaRecordValue, TxtRecordValue, WksRecordValue,
};
use crate::dns::{Ttl, name};
use crate::model::zone::ZoneId;

/// Return domain-name value types for case-insensitive comparison (RFC 4343).
/// Record-filter SQL shares this list across backends.
pub const NAME_LIKE_RECORD_TYPES: &[RecordType] = &[
    RecordType::Cname,
    RecordType::Dname,
    RecordType::Ns,
    RecordType::Ptr,
    RecordType::Mx,
    RecordType::Srv,
];

id_newtype!(
    /// The id of a record row.
    RecordId
);

/// One stored DNS record of a zone.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Record {
    pub id: RecordId,
    pub name: OwnerName,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Ttl,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub zone_id: ZoneId,
}

/// Canonical DNS record identity: owner, type and RDATA, excluding TTL and row id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordKey {
    name: OwnerName,
    record_type: RecordType,
    /// Canonical comparison form of the value, priority included for MX and SRV.
    rdata: String,
}

impl RecordKey {
    /// Build the identity of a record with these fields, canonicalizing its value once.
    pub fn new(
        owner: &OwnerName,
        record_type: RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Self {
        Self {
            name: owner.clone(),
            record_type,
            rdata: record_type.canonical_value(value, priority).into_owned(),
        }
    }
}

impl Record {
    /// Encode RDATA using the transfer and signer encoder.
    pub fn to_rdata(&self) -> Result<Rdata, EncodeRdataError> {
        Rdata::from_columns(self.record_type, &self.value, self.priority)
    }

    /// Return whether an RFC 2136, Section 2.5.2 delete by type, canonical value, and
    /// priority selects this record.
    /// MX and SRV priorities narrow separately because they occupy their own column.
    pub fn matches(
        &self,
        record_type: Option<RecordType>,
        value: Option<&str>,
        priority: Option<i32>,
    ) -> bool {
        if record_type.is_some_and(|wanted| wanted != self.record_type) {
            return false;
        }
        if value.is_some_and(|value| {
            !self
                .record_type
                .values_equal(&self.value, None, value, None)
        }) {
            return false;
        }

        priority.is_none_or(|wanted| self.priority == Some(wanted))
    }

    /// Return whether this row holds `value` as its rdata (with `priority`, for MX
    /// and SRV), compared canonically under the row's own type.
    pub fn has_rdata(&self, value: &str, priority: Option<i32>) -> bool {
        self.record_type
            .values_equal(&self.value, self.priority, value, priority)
    }

    /// Return whether an UPDATE adding a `record_type` value replaces this
    /// record by singleton type or WKS address/protocol.
    pub fn is_replaced_by(
        &self,
        record_type: RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> bool {
        if self.record_type != record_type || self.has_rdata(value, priority) {
            return false;
        }

        match self.record_type {
            RecordType::Cname | RecordType::Dname => true,
            RecordType::Wks => {
                let identity = |value| {
                    WksRecordValue::parse(value)
                        .ok()
                        .map(|parsed| parsed.address_and_protocol())
                };
                identity(&self.value).is_some_and(|existing| identity(value) == Some(existing))
            }
            _ => false,
        }
    }

    /// Return this record's identity for set matching, shared with [`RecordData`].
    pub fn match_key(&self) -> RecordKey {
        RecordKey::new(&self.name, self.record_type, &self.value, self.priority)
    }
}

/// The owner name and type identifying a record set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordSetKey {
    pub name: String,
    pub record_type: RecordType,
}

/// Record contents without row identity, zone or creation time,
/// used for journal replay and diffs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    pub name: OwnerName,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Ttl,
    pub priority: Option<i32>,
}

impl RecordData {
    /// Return this record's identity for set matching, shared with [`Record`].
    pub fn match_key(&self) -> RecordKey {
        RecordKey::new(&self.name, self.record_type, &self.value, self.priority)
    }
}

impl From<Record> for RecordData {
    /// Drop a stored record's row identity.
    fn from(record: Record) -> Self {
        Self {
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

/// A [`Record`] joined with the name of its owning zone.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct RecordWithZone {
    #[sqlx(flatten)]
    pub record: Record,
    pub zone_name: ZoneName,
}

/// A record type outside the user records bindizr stores, by mnemonic or by
/// wire type.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseRecordTypeError {
    #[error("invalid record type: {value}")]
    Unknown { value: String },
    #[error("unsupported record type: {value}")]
    Unsupported { value: Rtype },
}

/// The record types bindizr stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum RecordType {
    A,
    Aaaa,
    Caa,
    Cname,
    Dname,
    Ds,
    Mx,
    Naptr,
    Txt,
    Ns,
    Srv,
    Ptr,
    Sshfp,
    Tlsa,
    Wks,
}

impl RecordType {
    /// Every supported user record type, in its declaration order.
    pub const ALL: [Self; 15] = [
        Self::A,
        Self::Aaaa,
        Self::Caa,
        Self::Cname,
        Self::Dname,
        Self::Ds,
        Self::Mx,
        Self::Naptr,
        Self::Txt,
        Self::Ns,
        Self::Srv,
        Self::Ptr,
        Self::Sshfp,
        Self::Tlsa,
        Self::Wks,
    ];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Caa => "CAA",
            Self::Cname => "CNAME",
            Self::Dname => "DNAME",
            Self::Ds => "DS",
            Self::Mx => "MX",
            Self::Naptr => "NAPTR",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Srv => "SRV",
            Self::Ptr => "PTR",
            Self::Sshfp => "SSHFP",
            Self::Tlsa => "TLSA",
            Self::Wks => "WKS",
        }
    }

    /// Validate a stored value (and its priority column) for this record type.
    pub fn validate_value(
        self,
        value: &str,
        priority: Option<i32>,
    ) -> Result<(), ParseRecordValueError> {
        // Only MX and SRV encode a priority
        if priority.is_some() && !matches!(self, Self::Mx | Self::Srv) {
            return Err(ParseRecordValueError::PriorityNotTaken { record_type: self });
        }

        match self {
            Self::A => ARecordValue::parse(value).map(|_| ()),
            Self::Aaaa => AaaaRecordValue::parse(value).map(|_| ()),
            Self::Caa => CaaRecordValue::parse(value)?.validate(),
            Self::Cname => CnameRecordValue::parse(value).map(|_| ()),
            Self::Dname => DnameRecordValue::parse(value).map(|_| ()),
            Self::Ds => DsRecordValue::parse(value)?.validate(),
            Self::Mx => MxRecordValue::parse(value, priority)?.validate(),
            Self::Naptr => NaptrRecordValue::parse(value)?.validate(),
            Self::Txt => TxtRecordValue::from_row(value)?.validate(),
            Self::Ns => NsRecordValue::parse(value).map(|_| ()),
            Self::Srv => SrvRecordValue::parse(value, priority)?.validate(),
            Self::Ptr => PtrRecordValue::parse(value).map(|_| ()),
            Self::Sshfp => SshfpRecordValue::parse(value)?.validate(),
            Self::Tlsa => TlsaRecordValue::parse(value)?.validate(),
            Self::Wks => WksRecordValue::parse(value).map(|_| ()),
        }
    }

    /// Return whether two stored values (with their priority columns) name the same
    /// rdata for this record type.
    pub fn values_equal(
        self,
        left: &str,
        left_priority: Option<i32>,
        right: &str,
        right_priority: Option<i32>,
    ) -> bool {
        self.canonical_value(left, left_priority) == self.canonical_value(right, right_priority)
    }

    /// Return the stored priority: MX and SRV encode a preference in their rdata, so
    /// an omitted one takes the default serving applies; other types pass through
    /// to be rejected.
    pub fn stored_priority(self, priority: Option<i32>) -> Option<i32> {
        match self {
            Self::Mx | Self::Srv => Some(priority.unwrap_or(i32::from(DEFAULT_PRIORITY))),
            _ => priority,
        }
    }

    /// Return the canonical form used only to compare two values, never to store them.
    pub fn canonical_value<'a>(
        self,
        value: &'a str,
        fallback_priority: Option<i32>,
    ) -> Cow<'a, str> {
        self.encoded_value(value, fallback_priority)
            .ok()
            .and_then(|value| Rdata::from_columns(self, &value, fallback_priority).ok())
            .and_then(|rdata| rdata.to_canonical(Rtype::from(self)).ok())
            .map(|rdata| Cow::Owned(hex::encode(rdata.as_bytes())))
            .unwrap_or(Cow::Borrowed(value))
    }

    /// Render storage text, distinct from [`Self::canonical_value`]'s comparison form.
    /// TXT input starting with a quote is read as presentation form, anything
    /// else as raw text; segments, or raw text that may start with a quote, go
    /// through [`TxtRecordValue::from_segments`] or [`TxtRecordValue::from_string`].
    pub fn encoded_value(
        self,
        value: &str,
        priority: Option<i32>,
    ) -> Result<String, ParseRecordValueError> {
        // Names retain escaped whitespace; other grammars trim or parse their own fields.
        let trimmed = value.trim();
        let name = name::trim_presentation_name(value);

        match self {
            Self::Wks => WksRecordValue::parse(value).map(|parsed| parsed.canonical()),
            Self::A => ARecordValue::parse(trimmed).map(ARecordValue::canonical),
            Self::Aaaa => AaaaRecordValue::parse(trimmed).map(AaaaRecordValue::canonical),
            Self::Caa => {
                let parsed = CaaRecordValue::parse(value)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            Self::Cname => CnameRecordValue::parse(name).map(CnameRecordValue::canonical),
            Self::Dname => DnameRecordValue::parse(name).map(DnameRecordValue::canonical),
            Self::Ds => {
                let parsed = DsRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            Self::Mx => {
                let parsed = MxRecordValue::parse(value, priority)?;
                parsed.validate()?;
                Ok(parsed.to_stored())
            }
            Self::Naptr => {
                let parsed = NaptrRecordValue::parse(value)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            Self::Txt => TxtRecordValue::parse(value).map(|parsed| parsed.to_presentation()),
            Self::Ns => NsRecordValue::parse(name).map(NsRecordValue::canonical),
            Self::Srv => {
                let parsed = SrvRecordValue::parse(value, priority)?;
                parsed.validate()?;
                Ok(parsed.to_stored())
            }
            Self::Ptr => PtrRecordValue::parse(name).map(PtrRecordValue::canonical),
            Self::Sshfp => {
                let parsed = SshfpRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            Self::Tlsa => {
                let parsed = TlsaRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
        }
    }

    /// Format a stored value of this record type for display: TXT decoded to
    /// its text, every other type as stored, its names already absolute.
    pub fn display_value(self, value: &str) -> String {
        if self == Self::Txt {
            return match TxtRecordValue::from_presentation(value)
                .ok()
                .and_then(|rdata| rdata.to_content())
            {
                Some(segments) => display_text(&segments.concat()),
                None => value.to_string(),
            };
        }

        value.to_string()
    }

    /// Render zone-file RDATA: the stored value, MX/SRV priority (default 10)
    /// first.
    pub fn presentation_rdata(self, value: &str, priority: Option<i32>) -> String {
        match self {
            Self::Mx | Self::Srv => {
                format!(
                    "{} {value}",
                    priority.unwrap_or(i32::from(DEFAULT_PRIORITY))
                )
            }
            _ => value.to_string(),
        }
    }
}

impl fmt::Display for RecordType {
    /// Write the record type in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = ParseRecordTypeError;

    /// Parse a record type from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "CAA" => Ok(Self::Caa),
            "CNAME" => Ok(Self::Cname),
            "DNAME" => Ok(Self::Dname),
            "DS" => Ok(Self::Ds),
            "MX" => Ok(Self::Mx),
            "NAPTR" => Ok(Self::Naptr),
            "TXT" => Ok(Self::Txt),
            "NS" => Ok(Self::Ns),
            "SRV" => Ok(Self::Srv),
            "PTR" => Ok(Self::Ptr),
            "SSHFP" => Ok(Self::Sshfp),
            "TLSA" => Ok(Self::Tlsa),
            "WKS" => Ok(Self::Wks),
            _ => Rtype::from_str(value)
                .map_err(|_| ParseRecordTypeError::Unknown {
                    value: value.to_string(),
                })
                .and_then(Self::try_from),
        }
    }
}

impl TryFrom<String> for RecordType {
    type Error = ParseRecordTypeError;

    /// Validate and convert the stored value into a record type.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

/// The write half: binding renders the canonical mnemonic, the row form
/// `TryFrom<String>` parses.
impl<DB: sqlx::Database> sqlx::Type<DB> for RecordType
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for RecordType
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.as_str().to_string().encode_by_ref(buffer)
    }
}

impl From<RecordType> for String {
    /// Render the canonical mnemonic for serde.
    fn from(record_type: RecordType) -> Self {
        record_type.as_str().to_string()
    }
}

impl TryFrom<Rtype> for RecordType {
    type Error = ParseRecordTypeError;

    /// Convert a wire record type to one of the record types bindizr stores as user records.
    /// SOA is excluded because it is managed through the zone's own fields.
    fn try_from(rtype: Rtype) -> Result<Self, Self::Error> {
        match rtype {
            Rtype::A => Ok(Self::A),
            Rtype::NS => Ok(Self::Ns),
            Rtype::CNAME => Ok(Self::Cname),
            Rtype::DNAME => Ok(Self::Dname),
            Rtype::PTR => Ok(Self::Ptr),
            Rtype::CAA => Ok(Self::Caa),
            Rtype::DS => Ok(Self::Ds),
            Rtype::SSHFP => Ok(Self::Sshfp),
            Rtype::TLSA => Ok(Self::Tlsa),
            Rtype::MX => Ok(Self::Mx),
            Rtype::NAPTR => Ok(Self::Naptr),
            Rtype::TXT => Ok(Self::Txt),
            Rtype::AAAA => Ok(Self::Aaaa),
            Rtype::SRV => Ok(Self::Srv),
            Rtype::WKS => Ok(Self::Wks),
            _ => Err(ParseRecordTypeError::Unsupported { value: rtype }),
        }
    }
}

impl From<RecordType> for Rtype {
    /// Convert a stored record type to the wire type its records carry.
    fn from(record_type: RecordType) -> Self {
        match record_type {
            RecordType::A => Self::A,
            RecordType::Ns => Self::NS,
            RecordType::Cname => Self::CNAME,
            RecordType::Dname => Self::DNAME,
            RecordType::Ptr => Self::PTR,
            RecordType::Caa => Self::CAA,
            RecordType::Ds => Self::DS,
            RecordType::Sshfp => Self::SSHFP,
            RecordType::Tlsa => Self::TLSA,
            RecordType::Mx => Self::MX,
            RecordType::Naptr => Self::NAPTR,
            RecordType::Txt => Self::TXT,
            RecordType::Aaaa => Self::AAAA,
            RecordType::Srv => Self::SRV,
            RecordType::Wks => Self::WKS,
        }
    }
}

impl Ord for RecordType {
    /// Preserve mnemonic ordering in record lists and diffs.
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for RecordType {
    /// Compare record types by their canonical mnemonic.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl utoipa::PartialSchema for RecordType {
    /// Describe the closed list of supported user record types.
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .schema_type(Type::String)
            .enum_values(Some(Self::ALL.map(Self::as_str)))
            .description(Some("Supported user record type. WKS values use <IPv4> <protocol> [ports...]. Unsupported types are rejected; SOA and signer-managed DNSSEC records have separate contracts."))
            .into()
    }
}

impl utoipa::ToSchema for RecordType {}

/// Render TXT text for the display column: control characters as `\DDD`, since a
/// text column cannot hold a NUL, and everything else as typed, for search.
fn display_text(text: &str) -> String {
    if !text.chars().any(|ch| ch.is_ascii_control()) {
        return text.to_string();
    }

    let mut display = String::with_capacity(text.len() + 4);

    for ch in text.chars() {
        if ch.is_ascii_control() {
            display.push_str(&format!("\\{:03}", ch as u8));
        } else {
            display.push(ch);
        }
    }

    display
}

#[cfg(test)]
mod tests;
