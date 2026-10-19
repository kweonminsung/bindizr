//! Record payloads, in three groups: the string-or-segments value form, the
//! request/filter/patch shapes, and the response shapes.

use bindizr_core::{
    dns::{
        Ttl,
        name::ZoneName,
        record::{ParseRecordValueError, TxtContent, TxtRecordValue},
    },
    model::{dnssec_record::DnssecRecordType, record::RecordId, role_grant::Action, zone::ZoneId},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::{IntoParams, ToSchema};

use super::version::RecordDiffResponse;
use crate::model::record::{Record, RecordType};

/// A request value that has no record-row form.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum EncodeRecordValueError {
    #[error("array value is only supported for TXT records")]
    SegmentsNotTxt,
    #[error("presentation value is only supported for TXT records")]
    PresentationNotTxt,
    #[error(transparent)]
    Value(#[from] ParseRecordValueError),
}

/// A record value as the API spells it, in requests and responses alike:
/// a single string, TXT segments, or explicit TXT presentation with DNS escapes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(untagged)]
pub enum RecordValue {
    #[schema(example = "192.168.1.100")]
    Text(String),
    #[schema(example = json!(["hello", "world"]))]
    Segments(Vec<String>),
    /// Quoted TXT character-strings with RFC 1035 escapes for arbitrary octets.
    Presentation { presentation: String },
}

impl RecordValue {
    /// The value as one string; TXT segments concatenate into the text they
    /// encode.
    pub fn to_text(&self) -> String {
        match self {
            RecordValue::Text(value) => value.clone(),
            RecordValue::Segments(segments) => segments.concat(),
            RecordValue::Presentation { presentation } => presentation.clone(),
        }
    }

    /// Encode the request value into its record-row form. A TXT string is raw
    /// content (never presentation form), so quotes carry no special meaning.
    pub(crate) fn to_encoded_value(
        &self,
        record_type: &RecordType,
        priority: Option<i32>,
    ) -> Result<String, EncodeRecordValueError> {
        match (record_type, self) {
            (RecordType::Txt, RecordValue::Text(value)) => {
                Ok(TxtRecordValue::from_string(value).to_presentation())
            }
            (RecordType::Txt, RecordValue::Segments(segments)) => Ok(
                TxtRecordValue::from_segments(segments.iter().map(String::as_str))
                    .map(|parsed| parsed.to_presentation())?,
            ),
            (RecordType::Txt, RecordValue::Presentation { presentation }) => {
                let parsed = TxtRecordValue::from_presentation(presentation)
                    .ok_or(ParseRecordValueError::TxtRdata)?;
                parsed.validate()?;
                Ok(parsed.to_presentation())
            }
            (_, RecordValue::Text(value)) => Ok(record_type.encoded_value(value, priority)?),
            (_, RecordValue::Segments(_)) => Err(EncodeRecordValueError::SegmentsNotTxt),
            (_, RecordValue::Presentation { .. }) => {
                Err(EncodeRecordValueError::PresentationNotTxt)
            }
        }
    }
}

/// A stored value as the record APIs display it: TXT decoded to string/segments,
/// other types rendered with trailing-dot FQDNs. Priority stays a separate field.
pub(crate) fn build_display_value(value: &str, record_type: &RecordType) -> RecordValue {
    if *record_type != RecordType::Txt {
        return RecordValue::Text(record_type.display_value(value));
    }
    match TxtRecordValue::from_presentation(value).and_then(|rdata| rdata.to_content()) {
        Some(TxtContent::Single(value)) => RecordValue::Text(value),
        Some(TxtContent::Segments(segments)) => RecordValue::Segments(segments),
        None => RecordValue::Presentation {
            presentation: value.to_string(),
        },
    }
}

/// Request body for creating a record in a named zone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValue,
    /// Optional; an omitted TTL is fixed to the zone's TTL at write time. Records sharing a name and type share one TTL.
    #[schema(example = 3600, value_type = Option<Ttl>, inline)]
    pub ttl: Option<i64>,
    /// MX and SRV priority, set here rather than inline in the value; other
    /// record types reject it. Omitted, it is served and compared as 10.
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

/// A record's data fields for a bulk insertion; the zone comes from the
/// request, so unlike [`CreateRecordRequest`] it carries no `zone_name`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkRecordItem {
    #[schema(example = "sub")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValue,
    /// Optional; an omitted TTL is fixed to the zone's TTL at write time. Records sharing a name and type share one TTL.
    #[schema(example = 3600, value_type = Option<Ttl>, inline)]
    pub ttl: Option<i64>,
    /// MX and SRV priority, set here rather than inline in the value; other
    /// record types reject it. Omitted, it is served and compared as 10.
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// Request body for bulk-inserting records into a zone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBulkRecordsRequest {
    #[schema(example = "example.com")]
    pub zone_name: String,
    pub records: Vec<BulkRecordItem>,
    /// When true, parse and validate without applying any change.
    #[serde(default)]
    pub dry_run: bool,
}

/// Request body for updating a record; an omitted field keeps the current
/// value, merged inside the update transaction. `value` is required when
/// `type` changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateRecordRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "sub")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "A")]
    pub record_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<RecordValue>,
    /// Records sharing a name and type share one TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 3600, value_type = Option<Ttl>, inline)]
    pub ttl: Option<i64>,
    /// MX and SRV priority; other record types reject it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 10)]
    pub priority: Option<i32>,
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

/// Delete or preview records at a required `zone_name` and `name`
/// (RFC 2136, Section 2.5.2); whole-zone deletion belongs to `DELETE /zones/{name}`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct DeleteRecordsRequest {
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// Owner name relative to the zone, or `@` for the apex.
    #[schema(example = "www")]
    pub name: String,
    /// Narrows to one type; omitted, every type at the name goes.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "A")]
    pub record_type: Option<String>,
    /// Canonical value match: one string or TXT segments, as in a create request. Requires `type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "192.0.2.1")]
    pub value: Option<RecordValue>,
    /// MX and SRV keep their preference in its own column, so it narrows
    /// there rather than being part of `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 10)]
    pub priority: Option<i32>,
    /// When true, report what would go without removing anything.
    #[serde(default)]
    pub dry_run: bool,
}

/// Deleted records or their preview; no matches leave the serial unchanged and send no NOTIFY.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct DeleteRecordsResponse {
    /// Whether this call wrote; a filter that matched nothing still ran, and
    /// says so with `deleted: 0`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 3)]
    pub deleted: u64,
    pub records: Vec<RecordResponse>,
    /// The removal as a record diff, for previewing the change.
    pub diff: RecordDiffResponse,
}

/// Query filters and pagination for listing records.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct RecordFilter {
    /// The name of the DNS zone to filter records by.
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    /// Filter by record name.
    #[schema(example = "sub")]
    pub name: Option<String>,
    /// Filter by record type.
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: Option<String>,
    /// Partially filter by record value.
    #[schema(example = "192.168.1.100")]
    pub value: Option<String>,
    /// Filter by TTL.
    #[schema(example = 3600, value_type = Option<Ttl>, inline)]
    #[param(value_type = Option<Ttl>, inline)]
    pub ttl: Option<i64>,
    /// Filter by minimum TTL.
    #[schema(example = 300, value_type = Option<Ttl>, inline)]
    #[param(value_type = Option<Ttl>, inline)]
    pub min_ttl: Option<i64>,
    /// Filter by maximum TTL.
    #[schema(example = 86400, value_type = Option<Ttl>, inline)]
    #[param(value_type = Option<Ttl>, inline)]
    pub max_ttl: Option<i64>,
    /// Filter by priority.
    #[schema(example = 10)]
    pub priority: Option<i32>,
    /// Filter by minimum priority.
    #[schema(example = 1)]
    pub min_priority: Option<i32>,
    /// Filter by maximum priority.
    #[schema(example = 20)]
    pub max_priority: Option<i32>,
    /// Partially search records.
    #[schema(example = "api")]
    pub search: Option<String>,
    /// `name` (the default), `type`, `ttl`, `priority`, or `created_at`.
    #[schema(example = "name")]
    pub sort: Option<String>,
    /// `asc` (the default) or `desc`.
    #[schema(example = "asc")]
    pub order: Option<String>,
    /// Include derived DNSSEC records after user records in the same pagination.
    /// Derived rows have no id; `type` accepts derived types and search matches names only.
    /// Priority filters exclude derived rows; value filters are rejected.
    #[schema(example = false)]
    pub signed: Option<bool>,
    /// Records per page; defaults to 50 when omitted, 1000 is the largest
    /// page accepted.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    /// Number of records to skip.
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// Record data with absolute, trailing-dot owner/RDATA names and a bare `zone_name`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RecordResponse {
    /// Absent on the derived DNSSEC rows of a signed listing, which are not
    /// addressable records.
    #[schema(example = 1, value_type = Option<i32>)]
    pub id: Option<RecordId>,
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: ServedRecordType,
    #[schema(example = "192.168.1.100")]
    pub value: RecordValue,
    #[schema(example = 3600, inline)]
    pub ttl: Ttl,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = 1, value_type = i32)]
    pub zone_id: ZoneId,
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// The record actions the caller may take on this record; empty on a
    /// derived DNSSEC row.
    pub actions: Vec<Action>,
}

impl RecordResponse {
    /// Render a record response with absolute names and the caller's actions.
    pub(crate) fn from_record(record: &Record, zone_name: &ZoneName, actions: Vec<Action>) -> Self {
        RecordResponse {
            id: record.id.written(),
            name: record.name.to_fqdn(zone_name),
            record_type: record.record_type.into(),
            value: build_display_value(&record.value, &record.record_type),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: zone_name.to_string(),
            actions,
        }
    }
}

/// A single record wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SingleRecordResponse {
    pub record: RecordResponse,
}

/// What a record write left behind, in the shape every previewable operation
/// answers with: whether it wrote, and the change as a record diff.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct WriteRecordResponse {
    /// Whether this call wrote; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub record: RecordResponse,
    /// The write as a record diff, for previewing it.
    pub diff: RecordDiffResponse,
}

/// Bulk-create result; previews contain validated records with placeholder IDs and write nothing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct CreateBulkRecordsResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 3)]
    pub added: u64,
    pub records: Vec<RecordResponse>,
    /// Dry-run diff; adding a value at an existing name and type is a changed group.
    pub diff: RecordDiffResponse,
}

/// The type of a record the zone serves: a user record type, or a
/// signer-generated one on a derived row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum ServedRecordType {
    User(RecordType),
    Derived(DnssecRecordType),
}

impl ServedRecordType {
    /// Render the canonical API mnemonic.
    pub fn to_text(self) -> String {
        match self {
            Self::User(value) => value.as_str().to_owned(),
            Self::Derived(value) => value.as_str().to_owned(),
        }
    }
}

impl std::fmt::Display for ServedRecordType {
    /// Display the canonical DNS mnemonic.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.to_text())
    }
}

impl From<RecordType> for ServedRecordType {
    /// Wrap a stored user record type for a record response.
    fn from(value: RecordType) -> Self {
        Self::User(value)
    }
}

impl From<DnssecRecordType> for ServedRecordType {
    /// Wrap a generated DNSSEC record type for a record response.
    fn from(value: DnssecRecordType) -> Self {
        Self::Derived(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep signed and plain record responses compatible with DNS mnemonic strings.
    #[test]
    fn record_type_response_spells_itself_once() {
        for (value, expected) in [
            (ServedRecordType::from(RecordType::A), "A"),
            (ServedRecordType::from(RecordType::Aaaa), "AAAA"),
            (ServedRecordType::from(RecordType::Caa), "CAA"),
            (ServedRecordType::from(RecordType::Cname), "CNAME"),
            (ServedRecordType::from(RecordType::Dname), "DNAME"),
            (ServedRecordType::from(RecordType::Ds), "DS"),
            (ServedRecordType::from(RecordType::Mx), "MX"),
            (ServedRecordType::from(RecordType::Naptr), "NAPTR"),
            (ServedRecordType::from(RecordType::Txt), "TXT"),
            (ServedRecordType::from(RecordType::Ns), "NS"),
            (ServedRecordType::from(RecordType::Srv), "SRV"),
            (ServedRecordType::from(RecordType::Ptr), "PTR"),
            (ServedRecordType::from(RecordType::Sshfp), "SSHFP"),
            (ServedRecordType::from(RecordType::Tlsa), "TLSA"),
            (ServedRecordType::from(RecordType::Wks), "WKS"),
            (ServedRecordType::from(DnssecRecordType::Rrsig), "RRSIG"),
            (ServedRecordType::from(DnssecRecordType::Nsec), "NSEC"),
            (ServedRecordType::from(DnssecRecordType::Dnskey), "DNSKEY"),
            (ServedRecordType::from(DnssecRecordType::Nsec3), "NSEC3"),
            (
                ServedRecordType::from(DnssecRecordType::Nsec3param),
                "NSEC3PARAM",
            ),
            (ServedRecordType::from(DnssecRecordType::Cds), "CDS"),
            (ServedRecordType::from(DnssecRecordType::Cdnskey), "CDNSKEY"),
        ] {
            assert_eq!(value.to_text(), expected);
            assert_eq!(value.to_string(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<ServedRecordType>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
        for invalid in ["SOA", "ANY", "AAAAA"] {
            assert!(
                serde_json::from_value::<ServedRecordType>(serde_json::json!(invalid)).is_err()
            );
        }
    }
}
