use std::borrow::Cow;

use chrono::{DateTime, Utc};
use domain::base::iana::Rtype;
use sqlx::FromRow;
use thiserror::Error;

use crate::{
    dns::{
        Ttl,
        name::{OwnerName, ZoneName, to_fqdn_lowercase},
        record::{
            ARecordValue, AaaaRecordValue, CaaRecordValue, CnameRecordValue, DEFAULT_PRIORITY,
            DnameRecordValue, DsRecordValue, MxRecordValue, NaptrRecordValue, NsRecordValue,
            ParseRecordValueError, PtrRecordValue, SrvRecordValue, SshfpRecordValue,
            TlsaRecordValue, TxtContent, TxtRecordValue,
        },
    },
    model::zone::ZoneId,
};

id_newtype!(
    /// The id of a record row.
    RecordId
);

/// One stored DNS record of a zone.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
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

/// What makes two records the same record to DNS: owner, type, and rdata,
/// compared canonically. TTL and the row id are left out: a TTL change is the
/// same record, and a rebuilt record has no row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordKey {
    name: OwnerName,
    record_type: RecordType,
    /// Canonical comparison form of the value, priority included for MX and SRV.
    rdata: String,
}

impl Record {
    /// Match an RFC 2136, Section 2.5.2 delete by type, canonical value, and priority.
    /// MX and SRV priorities narrow separately because they occupy their own column.
    pub fn matches(
        &self,
        record_type: Option<&RecordType>,
        value: Option<&str>,
        priority: Option<i32>,
    ) -> bool {
        if record_type.is_some_and(|wanted| *wanted != self.record_type) {
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

    /// Whether this row holds `value` as its rdata (with `priority`, for MX
    /// and SRV), compared canonically under the row's own type.
    pub fn has_rdata(&self, value: &str, priority: Option<i32>) -> bool {
        self.record_type
            .values_equal(&self.value, self.priority, value, priority)
    }

    /// This record's identity for set matching, shared with [`RecordData`].
    pub fn match_key(&self) -> RecordKey {
        RecordKey {
            name: self.name.clone(),
            record_type: self.record_type,
            rdata: self
                .record_type
                .canonical_value(&self.value, self.priority)
                .into_owned(),
        }
    }
}

/// The owner name and type identifying a record set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordSetKey {
    pub name: String,
    pub record_type: RecordType,
}

/// A record without its row identity: what a [`Record`] carries besides its
/// id, zone, and creation time. The form of a record rebuilt from the journal
/// and of the sets a diff compares, neither of which has a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    pub name: OwnerName,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Ttl,
    pub priority: Option<i32>,
}

impl From<Record> for RecordData {
    /// Drop a stored record's row identity.
    fn from(record: Record) -> Self {
        RecordData {
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

impl RecordData {
    /// This record's identity for set matching, shared with [`Record`].
    pub fn match_key(&self) -> RecordKey {
        RecordKey {
            name: self.name.clone(),
            record_type: self.record_type,
            rdata: self
                .record_type
                .canonical_value(&self.value, self.priority)
                .into_owned(),
        }
    }
}

/// A [`Record`] joined with the name of its owning zone.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct RecordWithZone {
    pub id: RecordId,
    pub name: OwnerName,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Ttl,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub zone_id: ZoneId,
    pub zone_name: ZoneName,
}

impl RecordWithZone {
    /// Return the underlying [`Record`], dropping the zone name.
    pub fn record(&self) -> Record {
        Record {
            id: self.id,
            name: self.name.clone(),
            record_type: self.record_type,
            value: self.value.clone(),
            ttl: self.ttl,
            priority: self.priority,
            created_at: self.created_at,
            zone_id: self.zone_id,
        }
    }
}

/// The record types bindizr stores.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "UPPERCASE")]
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
}

impl std::fmt::Display for RecordType {
    /// Write the record type in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// A record type outside the user records bindizr stores, by mnemonic or by
/// wire type.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseRecordTypeError {
    #[error("invalid record type: {0}")]
    Unknown(String),
    #[error("unsupported record type: {0}")]
    Unsupported(Rtype),
}

impl TryFrom<String> for RecordType {
    type Error = ParseRecordTypeError;

    /// Validate and convert the stored value into a record type.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
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

    /// Check whether the SQL type can store this value.
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
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.as_str().to_string().encode_by_ref(buf)
    }
}

impl std::str::FromStr for RecordType {
    type Err = ParseRecordTypeError;

    /// Parse a record type from its text representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::Aaaa),
            "CAA" => Ok(RecordType::Caa),
            "CNAME" => Ok(RecordType::Cname),
            "DNAME" => Ok(RecordType::Dname),
            "DS" => Ok(RecordType::Ds),
            "MX" => Ok(RecordType::Mx),
            "NAPTR" => Ok(RecordType::Naptr),
            "TXT" => Ok(RecordType::Txt),
            "NS" => Ok(RecordType::Ns),
            "SRV" => Ok(RecordType::Srv),
            "PTR" => Ok(RecordType::Ptr),
            "SSHFP" => Ok(RecordType::Sshfp),
            "TLSA" => Ok(RecordType::Tlsa),
            _ => Err(ParseRecordTypeError::Unknown(s.to_string())),
        }
    }
}

impl TryFrom<Rtype> for RecordType {
    type Error = ParseRecordTypeError;

    /// The record types bindizr stores as user records, keyed by wire record type.
    /// SOA is excluded because it is managed through the zone's own fields.
    fn try_from(rtype: Rtype) -> Result<Self, Self::Error> {
        match rtype {
            Rtype::A => Ok(RecordType::A),
            Rtype::NS => Ok(RecordType::Ns),
            Rtype::CNAME => Ok(RecordType::Cname),
            Rtype::DNAME => Ok(RecordType::Dname),
            Rtype::PTR => Ok(RecordType::Ptr),
            Rtype::CAA => Ok(RecordType::Caa),
            Rtype::DS => Ok(RecordType::Ds),
            Rtype::SSHFP => Ok(RecordType::Sshfp),
            Rtype::TLSA => Ok(RecordType::Tlsa),
            Rtype::MX => Ok(RecordType::Mx),
            Rtype::NAPTR => Ok(RecordType::Naptr),
            Rtype::TXT => Ok(RecordType::Txt),
            Rtype::AAAA => Ok(RecordType::Aaaa),
            Rtype::SRV => Ok(RecordType::Srv),
            _ => Err(ParseRecordTypeError::Unsupported(rtype)),
        }
    }
}

impl RecordType {
    /// Return the record type's presentation-format mnemonic (e.g. `"A"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Caa => "CAA",
            RecordType::Cname => "CNAME",
            RecordType::Dname => "DNAME",
            RecordType::Ds => "DS",
            RecordType::Mx => "MX",
            RecordType::Naptr => "NAPTR",
            RecordType::Txt => "TXT",
            RecordType::Ns => "NS",
            RecordType::Srv => "SRV",
            RecordType::Ptr => "PTR",
            RecordType::Sshfp => "SSHFP",
            RecordType::Tlsa => "TLSA",
        }
    }

    /// The record TYPE number this type's records carry on the wire.
    pub fn wire_type(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Dname => 39,
            RecordType::Ds => 43,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Naptr => 35,
            RecordType::Txt => 16,
            RecordType::Aaaa => 28,
            RecordType::Srv => 33,
            RecordType::Sshfp => 44,
            RecordType::Tlsa => 52,
            RecordType::Caa => 257,
        }
    }

    /// Validate a stored value (and its priority column) for this record type.
    pub fn validate_value(
        &self,
        value: &str,
        priority: Option<i32>,
    ) -> Result<(), ParseRecordValueError> {
        // Only MX and SRV encode a priority
        if priority.is_some() && !matches!(self, RecordType::Mx | RecordType::Srv) {
            return Err(ParseRecordValueError::PriorityNotTaken { record_type: *self });
        }

        match self {
            RecordType::A => ARecordValue::parse(value).map(|_| ()),
            RecordType::Aaaa => AaaaRecordValue::parse(value).map(|_| ()),
            RecordType::Caa => CaaRecordValue::parse(value)?.validate(),
            RecordType::Cname => CnameRecordValue::parse(value).map(|_| ()),
            RecordType::Dname => DnameRecordValue::parse(value).map(|_| ()),
            RecordType::Ds => DsRecordValue::parse(value)?.validate(),
            RecordType::Mx => MxRecordValue::parse(value, priority)?.validate(),
            RecordType::Naptr => NaptrRecordValue::parse(value)?.validate(),
            // Stored TXT is always the presentation form.
            RecordType::Txt => TxtRecordValue::from_presentation(value)
                .ok_or_else(|| ParseRecordValueError::StoredTxtNotPresentation {
                    value: value.to_string(),
                })?
                .validate(),
            RecordType::Ns => NsRecordValue::parse(value).map(|_| ()),
            RecordType::Srv => SrvRecordValue::parse(value, priority)?.validate(),
            RecordType::Ptr => PtrRecordValue::parse(value).map(|_| ()),
            RecordType::Sshfp => SshfpRecordValue::parse(value)?.validate(),
            RecordType::Tlsa => TlsaRecordValue::parse(value)?.validate(),
        }
    }

    /// Whether two stored values (with their priority columns) name the same
    /// rdata for this record type.
    pub fn values_equal(
        &self,
        left: &str,
        left_priority: Option<i32>,
        right: &str,
        right_priority: Option<i32>,
    ) -> bool {
        self.canonical_value(left, left_priority) == self.canonical_value(right, right_priority)
    }

    /// MX and SRV encode a preference in their rdata, so an omitted one takes
    /// the default serving applies; other types pass through to be rejected.
    pub fn stored_priority(&self, priority: Option<i32>) -> Option<i32> {
        match self {
            RecordType::Mx | RecordType::Srv => {
                Some(priority.unwrap_or(i32::from(DEFAULT_PRIORITY)))
            }
            _ => priority,
        }
    }

    /// Canonical form used only to compare two values, never to store them.
    pub fn canonical_value<'a>(
        &self,
        value: &'a str,
        fallback_priority: Option<i32>,
    ) -> Cow<'a, str> {
        match self {
            RecordType::A => ARecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Aaaa => AaaaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Caa => CaaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Cname | RecordType::Dname | RecordType::Ns | RecordType::Ptr => {
                Cow::Owned(to_fqdn_lowercase(value))
            }
            RecordType::Ds => DsRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Mx => MxRecordValue::parse(value, fallback_priority)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Naptr => NaptrRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            // Parsed like every other type, so the content a caller typed and
            // the presentation form the row holds compare equal.
            RecordType::Txt => TxtRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.to_presentation()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Srv => SrvRecordValue::parse(value, fallback_priority)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Sshfp => SshfpRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::Tlsa => TlsaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
        }
    }

    /// Counterpart of [`Self::canonical_value`] for writes: the one spelling
    /// record rows encode, so every entry path stores equal bytes. TXT takes
    /// presentation form; other TXT grammars go through [`TxtRecordValue`] directly.
    pub fn encoded_value(
        &self,
        value: &str,
        priority: Option<i32>,
    ) -> Result<String, ParseRecordValueError> {
        // TXT keeps raw bytes; every other type tolerates surrounding whitespace.
        let trimmed = value.trim();
        match self {
            RecordType::A => ARecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::Aaaa => AaaaRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::Caa => {
                let parsed = CaaRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::Cname => CnameRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::Dname => DnameRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::Ds => {
                let parsed = DsRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::Mx => {
                let parsed = MxRecordValue::parse(trimmed, priority)?;
                parsed.validate()?;
                Ok(parsed.to_stored())
            }
            RecordType::Naptr => {
                let parsed = NaptrRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::Txt => TxtRecordValue::parse(value).map(|parsed| parsed.to_presentation()),
            RecordType::Ns => NsRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::Srv => {
                let parsed = SrvRecordValue::parse(trimmed, priority)?;
                parsed.validate()?;
                Ok(parsed.to_stored())
            }
            RecordType::Ptr => PtrRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::Sshfp => {
                let parsed = SshfpRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::Tlsa => {
                let parsed = TlsaRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
        }
    }

    /// Format a stored value of this record type for display.
    pub fn display_value(&self, value: &str) -> String {
        if *self == RecordType::Txt {
            return match TxtRecordValue::from_presentation(value)
                .and_then(|rdata| rdata.to_content())
            {
                Some(TxtContent::Single(value)) => to_display_text(&value),
                Some(TxtContent::Segments(segments)) => to_display_text(&segments.join("")),
                None => value.to_string(),
            };
        }

        match self {
            RecordType::Mx => display_last_name_field(value, 1),
            RecordType::Srv => display_last_name_field(value, 3),
            _ if self.is_name_like() => to_fqdn_lowercase(value),
            _ => value.to_string(),
        }
    }

    /// Whether this type's display form is a domain name.
    fn is_name_like(&self) -> bool {
        NAME_LIKE_RECORD_TYPES.contains(self)
    }

    /// Render a stored value plus its priority column as zone-file rdata:
    /// MX/SRV carry the priority inline (default 10), TXT rows already hold
    /// their presentation form, and other types use their display form.
    pub fn presentation_rdata(&self, value: &str, priority: Option<i32>) -> String {
        match self {
            RecordType::Txt => value.to_string(),
            RecordType::Mx | RecordType::Srv => {
                format!(
                    "{} {}",
                    priority.unwrap_or(i32::from(DEFAULT_PRIORITY)),
                    self.display_value(value)
                )
            }
            _ => self.display_value(value),
        }
    }

    /// Whether the ExternalDNS provider manages records of this type
    /// ([`EXTERNAL_DNS_RECORD_TYPES`]).
    pub fn is_external_dns_supported(&self) -> bool {
        EXTERNAL_DNS_RECORD_TYPES.contains(self)
    }

    /// Parse a type name the ExternalDNS provider manages; `None` for an
    /// unknown or unsupported one.
    pub fn parse_external_dns_supported(value: &str) -> Option<Self> {
        let parsed = value.parse::<RecordType>().ok()?;
        parsed.is_external_dns_supported().then_some(parsed)
    }
}

/// TXT text for the display column: control characters as `\DDD`, since a
/// text column cannot hold a NUL, and everything else as typed, for search.
fn to_display_text(text: &str) -> String {
    if !text.chars().any(|c| c.is_ascii_control()) {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len() + 4);
    for c in text.chars() {
        if c.is_ascii_control() {
            out.push_str(&format!("\\{:03}", c as u8));
        } else {
            out.push(c);
        }
    }
    out
}

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

/// Record types the ExternalDNS provider manages. The API server and the
/// webhook adapter share no crate below core, so the set lives here rather
/// than being spelled out in each.
pub const EXTERNAL_DNS_RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::Aaaa,
    RecordType::Cname,
    RecordType::Txt,
];

/// Render the stored trailing domain name; MX priority is stored separately,
/// and SRV retains only weight, port, and target in its value.
fn display_last_name_field(value: &str, field_count: usize) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();

    if fields.len() != field_count {
        return value.to_string();
    }

    let Some(last) = fields.pop() else {
        return value.to_string();
    };
    fields.push(to_fqdn_lowercase(&last));
    fields.join(" ")
}

#[cfg(test)]
mod tests;

impl Ord for RecordType {
    /// Preserve mnemonic ordering in record lists and diffs.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for RecordType {
    /// Compare record types by their canonical mnemonic.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
