//! Record payloads, in three groups: the string-or-segments value form, the
//! request/filter/patch shapes, and the response shapes.

use bindizr_core::{
    dns::{
        name::ZoneName,
        record::{TxtContent, TxtRecordValue},
    },
    model::written_id,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::version::RecordDiff;
use crate::model::record::{Record, RecordType, RecordWithZone};

/// A record value as sent by the client: a single string or TXT segments.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum RecordValueRequest {
    #[schema(example = "192.168.1.100")]
    String(String),
    #[schema(example = json!(["hello", "world"]))]
    Segments(Vec<String>),
}

impl RecordValueRequest {
    /// The value as one string; TXT segments concatenate into the text they
    /// encode.
    pub fn to_text(&self) -> String {
        match self {
            RecordValueRequest::String(value) => value.clone(),
            RecordValueRequest::Segments(segments) => segments.concat(),
        }
    }

    /// Encode the request value into its record-row form. A TXT string is raw
    /// content (never presentation form), so quotes carry no special meaning.
    pub(crate) fn to_encoded_value(
        &self,
        record_type: &RecordType,
        priority: Option<i32>,
    ) -> Result<String, String> {
        match (record_type, self) {
            (RecordType::TXT, RecordValueRequest::String(value)) => {
                Ok(TxtRecordValue::from_string(value).to_presentation())
            }
            (RecordType::TXT, RecordValueRequest::Segments(segments)) => {
                TxtRecordValue::from_segments(segments.iter().map(String::as_str))
                    .map(|parsed| parsed.to_presentation())
            }
            (_, RecordValueRequest::String(value)) => record_type.encoded_value(value, priority),
            (_, RecordValueRequest::Segments(_)) => {
                Err("array value is only supported for TXT records".to_string())
            }
        }
    }
}

/// A stored value as the record APIs display it: TXT decoded to string/segments,
/// other types rendered with trailing-dot FQDNs. Priority stays a separate field.
pub(crate) fn build_display_value(value: &str, record_type: &RecordType) -> RecordValueRequest {
    if *record_type != RecordType::TXT {
        return RecordValueRequest::String(record_type.display_value(value));
    }
    match TxtRecordValue::from_presentation(value).and_then(|rdata| rdata.to_content()) {
        Some(TxtContent::Single(value)) => RecordValueRequest::String(value),
        Some(TxtContent::Segments(segments)) => RecordValueRequest::Segments(segments),
        None => RecordValueRequest::String(value.to_string()),
    }
}

/// Request body for creating a record in a named zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    /// Optional; an omitted TTL is fixed to the zone's TTL at write time. Records sharing a name and type share one TTL.
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
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
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordItem {
    #[schema(example = "sub")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    /// Optional; an omitted TTL is fixed to the zone's TTL at write time. Records sharing a name and type share one TTL.
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    /// MX and SRV priority, set here rather than inline in the value; other
    /// record types reject it. Omitted, it is served and compared as 10.
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// Request body for bulk-inserting records into a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBulkRecordsRequest {
    #[schema(example = "example.com")]
    pub zone_name: String,
    pub records: Vec<RecordItem>,
    /// When true, parse and validate without applying any change.
    #[serde(default)]
    pub dry_run: bool,
}

/// Request body for updating a record; an omitted field keeps the current
/// value, merged inside the update transaction. `value` is required when
/// `type` changes.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateRecordRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "sub")]
    pub name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "A")]
    pub record_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<RecordValueRequest>,
    /// Records sharing a name and type share one TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    /// MX and SRV priority; other record types reject it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 10)]
    pub priority: Option<i32>,
    /// Validate and report the change without writing it.
    #[serde(default)]
    #[schema(example = false)]
    pub dry_run: bool,
}

/// Which records a conditional delete removes, narrowing from a whole name
/// down to one record, as RFC 2136, Section 2.5.2 spells the same three forms.
/// `zone_name` and `name` are both required: without a name this would be a
/// second, quieter way to empty a zone, which `DELETE /zones/{name}` owns.
#[derive(Clone, Debug, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct DeleteRecordsFilter {
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// Owner name relative to the zone, or `@` for the apex.
    #[schema(example = "www")]
    pub name: String,
    /// Narrows to one type; omitted, every type at the name goes.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "A")]
    pub record_type: Option<String>,
    /// Narrows to one record, named the way a create names it: one string,
    /// or the segments of a TXT record. Compared canonically, so a value
    /// spelled another way still matches. Requires `type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "192.0.2.1")]
    pub value: Option<RecordValueRequest>,
    /// MX and SRV keep their preference in its own column, so it narrows
    /// there rather than being part of `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 10)]
    pub priority: Option<i32>,
    /// When true, report what would go without removing anything.
    #[serde(default)]
    pub dry_run: bool,
}

/// What a conditional delete removed, or would have. Matching nothing is not
/// an error: the zone already reads the way the request asked for, so the
/// serial does not move and no NOTIFY goes out.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DeleteRecordsResponse {
    /// Whether this call wrote; a filter that matched nothing still ran, and
    /// says so with `deleted: 0`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 3)]
    pub deleted: u64,
    pub records: Vec<GetRecordResponse>,
    /// The removal as a record diff, for previewing the change.
    pub diff: RecordDiff,
}

/// Query filters and pagination for listing records.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct GetRecordsFilter {
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
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    /// Filter by minimum TTL.
    #[schema(example = 300)]
    pub min_ttl: Option<i32>,
    /// Filter by maximum TTL.
    #[schema(example = 86400)]
    pub max_ttl: Option<i32>,
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
    /// Append the zone's derived DNSSEC records (RRSIG, DNSKEY,
    /// NSEC/NSEC3/NSEC3PARAM, CDS, CDNSKEY) after the user records, in the
    /// same pagination. Derived rows carry no id, and `type` also accepts a
    /// derived type. A search narrows them by name only, a priority filter
    /// leaves them out, and a value filter is refused rather than answered
    /// without them.
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

/// API representation of a record. `name` is the owner's absolute name with
/// its trailing dot, as name-valued rdata is rendered; `zone_name` is the
/// zone's bare name, the spelling `/zones/{name}` takes.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetRecordResponse {
    /// Absent on the derived DNSSEC rows of a signed listing, which are not
    /// addressable records.
    #[schema(example = 1)]
    pub id: Option<i32>,
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[serde(rename = "type")]
    #[schema(example = "A")]
    pub record_type: String,
    #[schema(example = "192.168.1.100")]
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = 1)]
    pub zone_id: i32,
    #[schema(example = "example.com")]
    pub zone_name: String,
}

impl GetRecordResponse {
    /// Build a response from a [`Record`], rendering owner/value as display names within `zone_name`.
    pub(crate) fn from_record_and_zone_name(record: &Record, zone_name: &ZoneName) -> Self {
        GetRecordResponse {
            id: written_id(record.id),
            name: record.name.to_fqdn(zone_name),
            record_type: record.record_type.to_string(),
            value: build_display_value(&record.value, &record.record_type),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: zone_name.to_string(),
        }
    }

    /// Build a record response using the record and its zone metadata.
    pub fn from_record_with_zone(record: &RecordWithZone) -> Self {
        Self::from_record_and_zone_name(&record.record(), &record.zone_name)
    }
}

/// A single record wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct RecordResponse {
    pub record: GetRecordResponse,
}

/// What a record write left behind, in the shape every previewable operation
/// answers with: whether it wrote, and the change as a record diff.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct RecordWriteResponse {
    /// Whether this call wrote; a dry run answers `false`.
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub record: GetRecordResponse,
    /// The write as a record diff, for previewing it.
    pub diff: RecordDiff,
}

/// Response for a bulk insert: the count added and the created records. On a
/// dry run `records` holds the validated would-be records (with placeholder
/// IDs) and nothing is added.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct BulkRecordsResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 3)]
    pub added: u64,
    pub records: Vec<GetRecordResponse>,
    /// Dry-run diff; adding a value at an existing name and type is a changed group.
    pub diff: RecordDiff,
}
