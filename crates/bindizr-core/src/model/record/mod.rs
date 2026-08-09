use std::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;

use crate::dns::{
    name::to_fqdn_lowercase,
    record::{
        ARecordValue, AaaaRecordValue, CnameRecordValue, MxRecordValue, NsRecordValue,
        PtrRecordValue, SoaRecordValue, SrvRecordValue, TxtContent, TxtRdata, TxtRecordValue,
    },
};

/// A single DNS resource record belonging to a zone.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Record {
    pub id: i32,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: i32,              // TTL in seconds
    pub priority: Option<i32>, // Priority (MX and SRV records)
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
}

/// A [`Record`] joined with the name of its owning zone.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct RecordWithZone {
    pub id: i32,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
    pub zone_name: String,
}

impl RecordWithZone {
    /// Create a [`RecordWithZone`] from a [`Record`] and its zone name.
    pub fn new(record: Record, zone_name: String) -> Self {
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
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    PTR,
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

impl std::str::FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "NS" => Ok(RecordType::NS),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "PTR" => Ok(RecordType::PTR),
            _ => Err(format!("Invalid record type: {}", s)),
        }
    }
}

impl RecordType {
    /// Return the record type's presentation-format mnemonic (e.g. `"A"`).
    pub fn as_str(&self) -> &str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::PTR => "PTR",
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
            RecordType::CNAME => CnameRecordValue::parse(value).map(|_| ()),
            RecordType::MX => MxRecordValue::parse(value, priority)?.validate(),
            RecordType::TXT => {
                let _ = TxtRecordValue::parse(value);
                Ok(())
            }
            RecordType::NS => NsRecordValue::parse(value).map(|_| ()),
            RecordType::SOA => SoaRecordValue::parse(value)?.validate(),
            RecordType::SRV => SrvRecordValue::parse(value, priority)?.validate(),
            RecordType::PTR => PtrRecordValue::parse(value).map(|_| ()),
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
            RecordType::CNAME => CnameRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or_else(|_| Cow::Owned(to_fqdn_lowercase(value))),
            RecordType::MX => MxRecordValue::parse(value, fallback_priority)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::TXT => TxtRecordValue::parse(value).canonical(),
            RecordType::NS => NsRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or_else(|_| Cow::Owned(to_fqdn_lowercase(value))),
            RecordType::SOA => SoaRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::SRV => SrvRecordValue::parse(value, fallback_priority)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or(Cow::Borrowed(value)),
            RecordType::PTR => PtrRecordValue::parse(value)
                .map(|parsed| Cow::Owned(parsed.canonical()))
                .unwrap_or_else(|_| Cow::Owned(to_fqdn_lowercase(value))),
        }
    }

    /// Counterpart of [`Self::canonical_value`] for writes: the one spelling
    /// record rows encode, so every entry path stores equal bytes. TXT takes
    /// presentation form; other TXT grammars go through [`TxtRdata`] directly.
    pub fn encoded_value(&self, value: &str, priority: Option<i32>) -> Result<String, String> {
        // TXT keeps raw bytes; every other type tolerates surrounding whitespace.
        let trimmed = value.trim();
        match self {
            RecordType::TXT => TxtRdata::from_presentation(value).map(TxtRdata::into_encoded),
            RecordType::A => ARecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::AAAA => AaaaRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::CNAME => CnameRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::NS => NsRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::PTR => PtrRecordValue::parse(trimmed).map(|parsed| parsed.canonical()),
            RecordType::MX => {
                let parsed = MxRecordValue::parse(trimmed, priority)?;
                parsed.validate()?;
                Ok(parsed.encoded())
            }
            RecordType::SRV => {
                let parsed = SrvRecordValue::parse(trimmed, priority)?;
                parsed.validate()?;
                Ok(parsed.encoded())
            }
            RecordType::SOA => {
                let parsed = SoaRecordValue::parse(trimmed)?;
                parsed.validate()?;
                Ok(parsed.canonical())
            }
        }
    }

    /// The MX wire fields of a stored value, so encoders do not re-derive the
    /// stored grammar.
    pub fn mx_wire_fields(value: &str, priority: Option<i32>) -> Result<(u16, &str), String> {
        MxRecordValue::wire_fields(value, priority)
    }

    /// The SRV wire fields of a stored value.
    pub fn srv_wire_fields(
        value: &str,
        priority: Option<i32>,
    ) -> Result<(u16, u16, u16, &str), String> {
        SrvRecordValue::wire_fields(value, priority)
    }

    /// Format a stored value of this record type for display.
    pub fn display_value(&self, value: &str) -> String {
        if *self == RecordType::TXT {
            return match TxtRdata::from_encoded(value).and_then(|rdata| rdata.to_content()) {
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
    /// MX/SRV carry the priority inline (default 10), TXT is quoted per
    /// character-string, and other types use their display form.
    pub fn presentation_rdata(&self, value: &str, priority: Option<i32>) -> String {
        match self {
            RecordType::TXT => match TxtRdata::from_encoded(value) {
                Some(rdata) => rdata.to_presentation(),
                // Not an encoded TXT value; quote it as a single character-string.
                None => TxtRdata::quote_charstr(value.as_bytes()),
            },
            RecordType::MX | RecordType::SRV => {
                format!("{} {}", priority.unwrap_or(10), self.display_value(value))
            }
            _ => self.display_value(value),
        }
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
