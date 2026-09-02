use std::borrow::Cow;

use chrono::{DateTime, Utc};
use domain::base::iana::Rtype;
use sqlx::FromRow;

use crate::dns::{
    name::{OwnerName, ZoneName, to_fqdn_lowercase},
    record::{
        ARecordValue, AaaaRecordValue, CaaRecordValue, CnameRecordValue, DsRecordValue,
        MxRecordValue, NsRecordValue, PtrRecordValue, SrvRecordValue, SshfpRecordValue,
        TlsaRecordValue, TxtContent, TxtRecordValue,
    },
};

/// A single DNS resource record belonging to a zone.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Record {
    pub id: i32,
    #[sqlx(try_from = "String")]
    pub name: OwnerName,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
}

/// A [`Record`] joined with the name of its owning zone.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct RecordWithZone {
    pub(crate) id: i32,
    #[sqlx(try_from = "String")]
    pub(crate) name: OwnerName,
    #[sqlx(try_from = "String")]
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
    pub(crate) ttl: i32,
    pub(crate) priority: Option<i32>,
    pub(crate) created_at: DateTime<Utc>,
    pub zone_id: i32,
    #[sqlx(try_from = "String")]
    pub zone_name: ZoneName,
}

impl RecordWithZone {
    /// Create a [`RecordWithZone`] from a [`Record`] and its zone name.
    pub fn new(record: Record, zone_name: ZoneName) -> Self {
        Self {
            id: record.id,
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
            created_at: record.created_at,
            zone_id: record.zone_id,
            zone_name,
        }
    }

    /// Return the underlying [`Record`], dropping the zone name.
    pub fn record(&self) -> Record {
        Record {
            id: self.id,
            name: self.name.clone(),
            record_type: self.record_type.clone(),
            value: self.value.clone(),
            ttl: self.ttl,
            priority: self.priority,
            created_at: self.created_at,
            zone_id: self.zone_id,
        }
    }
}

/// Supported DNS resource record types.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RecordType {
    A,
    AAAA,
    CAA,
    CNAME,
    DS,
    MX,
    TXT,
    NS,
    SRV,
    PTR,
    SSHFP,
    TLSA,
}
impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for RecordType {
    type Error = String;
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
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for RecordType
where
    String: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.as_str().to_string().encode_by_ref(buf)
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CAA" => Ok(RecordType::CAA),
            "CNAME" => Ok(RecordType::CNAME),
            "DS" => Ok(RecordType::DS),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "NS" => Ok(RecordType::NS),
            "SRV" => Ok(RecordType::SRV),
            "PTR" => Ok(RecordType::PTR),
            "SSHFP" => Ok(RecordType::SSHFP),
            "TLSA" => Ok(RecordType::TLSA),
            _ => Err(format!("Invalid record type: {}", s)),
        }
    }
}

impl RecordType {
    /// Return the record type's presentation-format mnemonic (e.g. `"A"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CAA => "CAA",
            RecordType::CNAME => "CNAME",
            RecordType::DS => "DS",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SRV => "SRV",
            RecordType::PTR => "PTR",
            RecordType::SSHFP => "SSHFP",
            RecordType::TLSA => "TLSA",
        }
    }

    /// The RR types bindizr stores as user records, keyed by wire RR type.
    /// SOA is excluded because it is managed through the zone's own fields.
    pub fn from_rtype(rtype: Rtype) -> Result<RecordType, String> {
        match rtype {
            Rtype::A => Ok(RecordType::A),
            Rtype::NS => Ok(RecordType::NS),
            Rtype::CNAME => Ok(RecordType::CNAME),
            Rtype::PTR => Ok(RecordType::PTR),
            Rtype::CAA => Ok(RecordType::CAA),
            Rtype::DS => Ok(RecordType::DS),
            Rtype::SSHFP => Ok(RecordType::SSHFP),
            Rtype::TLSA => Ok(RecordType::TLSA),
            Rtype::MX => Ok(RecordType::MX),
            Rtype::TXT => Ok(RecordType::TXT),
            Rtype::AAAA => Ok(RecordType::AAAA),
            Rtype::SRV => Ok(RecordType::SRV),
            _ => Err(format!("unsupported rr type: {}", rtype)),
        }
    }

    /// The RR TYPE number this type's records carry on the wire.
    pub fn wire_type(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::DS => 43,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::SSHFP => 44,
            RecordType::TLSA => 52,
            RecordType::CAA => 257,
        }
    }

    /// Validate a stored value (and its priority column) for this record type.
    /// Errors are plain messages; callers map them to their own error kind.
    pub fn validate_value(&self, value: &str, priority: Option<i32>) -> Result<(), String> {
        // Only MX and SRV encode a priority
        if priority.is_some() && !matches!(self, RecordType::MX | RecordType::SRV) {
            return Err(format!("{} records do not take a priority", self));
        }

        match self {
            RecordType::A => ARecordValue::parse(value).map(|_| ()),
            RecordType::AAAA => AaaaRecordValue::parse(value).map(|_| ()),
            RecordType::CAA => CaaRecordValue::parse(value)?.validate(),
            RecordType::CNAME => CnameRecordValue::parse(value).map(|_| ()),
            RecordType::DS => DsRecordValue::parse(value)?.validate(),
            RecordType::MX => MxRecordValue::parse(value, priority)?.validate(),
            // Stored TXT is always the presentation form.
            RecordType::TXT => TxtRecordValue::from_presentation(value)
                .ok_or_else(|| format!("stored TXT value is not in presentation form: {value}"))?
                .validate(),
            RecordType::NS => NsRecordValue::parse(value).map(|_| ()),
            RecordType::SRV => SrvRecordValue::parse(value, priority)?.validate(),
            RecordType::PTR => PtrRecordValue::parse(value).map(|_| ()),
            RecordType::SSHFP => SshfpRecordValue::parse(value)?.validate(),
            RecordType::TLSA => TlsaRecordValue::parse(value)?.validate(),
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
            RecordType::AAAA => AaaaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::CAA => CaaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::CNAME => CnameRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or_else(|_| Cow::Owned(to_fqdn_lowercase(value))),
            RecordType::DS => DsRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::MX => MxRecordValue::parse(value, fallback_priority)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::TXT => Cow::Borrowed(value),
            RecordType::NS => NsRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or_else(|_| Cow::Owned(to_fqdn_lowercase(value))),
            RecordType::SRV => SrvRecordValue::parse(value, fallback_priority)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::PTR => PtrRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or_else(|_| Cow::Owned(to_fqdn_lowercase(value))),
            RecordType::SSHFP => SshfpRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::TLSA => TlsaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
        }
    }

    /// Counterpart of [`Self::canonical_value`] for writes: the one spelling
    /// record rows encode, so every entry path stores equal bytes. TXT takes
    /// presentation form; other TXT grammars go through [`TxtRecordValue`] directly.
    pub fn encoded_value(&self, value: &str, priority: Option<i32>) -> Result<String, String> {
        // TXT keeps raw bytes; every other type tolerates surrounding whitespace.
        let trimmed = value.trim();
        match self {
            RecordType::A => ARecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::AAAA => AaaaRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::CAA => {
                let parsed = CaaRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::CNAME => CnameRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::DS => {
                let parsed = DsRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::MX => {
                let parsed = MxRecordValue::parse(trimmed, priority)?;
                parsed.validate()?;
                Ok(parsed.encoded())
            }
            RecordType::TXT => TxtRecordValue::parse(value).map(|parsed| parsed.to_presentation()),
            RecordType::NS => NsRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::SRV => {
                let parsed = SrvRecordValue::parse(trimmed, priority)?;
                parsed.validate()?;
                Ok(parsed.encoded())
            }
            RecordType::PTR => PtrRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::SSHFP => {
                let parsed = SshfpRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
            RecordType::TLSA => {
                let parsed = TlsaRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
        }
    }

    /// Format a stored value of this record type for display.
    pub fn display_value(&self, value: &str) -> String {
        if *self == RecordType::TXT {
            return match TxtRecordValue::from_presentation(value)
                .and_then(|rdata| rdata.to_content())
            {
                Some(TxtContent::Single(value)) => value,
                Some(TxtContent::Segments(segments)) => segments.join(""),
                None => value.to_string(),
            };
        }

        match self {
            RecordType::MX => display_last_name_field(value, MX_FIELD_COUNTS),
            RecordType::SRV => display_last_name_field(value, SRV_FIELD_COUNTS),
            _ if self.is_name_like() => to_fqdn_lowercase(value),
            _ => value.to_string(),
        }
    }

    /// Whether this type's display form is a domain name.
    pub fn is_name_like(&self) -> bool {
        NAME_LIKE_RECORD_TYPES.contains(self)
    }

    /// Render a stored value plus its priority column as zone-file rdata:
    /// MX/SRV carry the priority inline (default 10), TXT rows already hold
    /// their presentation form, and other types use their display form.
    pub fn presentation_rdata(&self, value: &str, priority: Option<i32>) -> String {
        match self {
            RecordType::TXT => value.to_string(),
            RecordType::MX | RecordType::SRV => {
                format!("{} {}", priority.unwrap_or(10), self.display_value(value))
            }
            _ => self.display_value(value),
        }
    }

    /// Whether the ExternalDNS provider manages records of this type
    /// ([`EXTERNAL_DNS_RECORD_TYPES`]).
    pub fn is_external_dns_supported(&self) -> bool {
        EXTERNAL_DNS_RECORD_TYPES.contains(self)
    }
}

/// Types whose display form is a domain name, so their values compare
/// case-insensitively (RFC 4343). The record-filter SQL selects on this same
/// set, which is why it is rendered from here rather than spelled out per
/// backend.
pub const NAME_LIKE_RECORD_TYPES: &[RecordType] = &[
    RecordType::CNAME,
    RecordType::NS,
    RecordType::PTR,
    RecordType::MX,
    RecordType::SRV,
];

/// Record types the ExternalDNS provider manages. The API server and the
/// webhook adapter share no crate below core, so the set lives here rather
/// than being spelled out in each.
pub const EXTERNAL_DNS_RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::TXT,
];

// The priority lives in its own column, never in the value: MX stores `target`
// and SRV `weight port target`.
const MX_FIELD_COUNTS: &[usize] = &[1];
const SRV_FIELD_COUNTS: &[usize] = &[3];

fn display_last_name_field(value: &str, valid_field_counts: &[usize]) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();

    if !valid_field_counts.contains(&fields.len()) {
        return value.to_string();
    }

    let last = fields.pop().expect("valid field count guarantees a target");
    fields.push(to_fqdn_lowercase(&last));
    fields.join(" ")
}

#[cfg(test)]
mod tests;
