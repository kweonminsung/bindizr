//! Record payloads, in three groups: the string-or-segments value form, the
//! request/filter/patch shapes, and the response shapes.

use bindizr_core::dns::{
    name::ZoneName,
    record::{TxtContent, TxtRecordValue},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
pub(crate) fn display_record_value_request(
    value: &str,
    record_type: &RecordType,
) -> RecordValueRequest {
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
pub struct CreateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    /// Optional; an omitted TTL is fixed to the zone's TTL at write time. Every record of an RRset (same name and type) must share one TTL.
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    /// MX and SRV priority, set here rather than inline in the value; other record types reject it.
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = "example.com")]
    pub zone_name: String,
}

/// A record's data fields, used both as a bulk-insertion entry and as the
/// record update request body. The zone is taken from the request path, so
/// unlike [`CreateRecordRequest`] it carries no `zone_name`.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct RecordItem {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    /// Optional; an omitted TTL is fixed to the zone's TTL at write time. Every record of an RRset (same name and type) must share one TTL.
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    /// MX and SRV priority, set here rather than inline in the value; other record types reject it.
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// Request body for bulk-inserting records into a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateBulkRecordsRequest {
    pub records: Vec<RecordItem>,
    /// When true, parse and validate without applying any change.
    #[serde(default, alias = "dryRun")]
    pub dry_run: bool,
}

/// A partial record update; an omitted field keeps the current value. Merged
/// inside the update transaction so a concurrent write is not lost.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UpdateRecordPatch {
    pub name: Option<String>,
    pub record_type: Option<String>,
    pub value: Option<RecordValueRequest>,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

/// Query filters and pagination for listing records.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct GetRecordsFilter {
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    #[schema(example = "sub")]
    pub name: Option<String>,
    #[schema(example = "A")]
    pub record_type: Option<String>,
    #[schema(example = "192.168.1.100")]
    pub value: Option<String>,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 300)]
    pub min_ttl: Option<i32>,
    #[schema(example = 86400)]
    pub max_ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = 1)]
    pub min_priority: Option<i32>,
    #[schema(example = 20)]
    pub max_priority: Option<i32>,
    #[serde(alias = "q")]
    #[schema(example = "api")]
    pub search: Option<String>,
    /// With true, the derived DNSSEC records page after the user records.
    #[schema(example = false)]
    pub signed: Option<bool>,
    #[schema(example = 50)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// API representation of a record, optionally carrying its zone name.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetRecordResponse {
    /// Absent on the derived DNSSEC rows of a signed listing, which are not
    /// addressable records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 1)]
    pub id: Option<i32>,
    #[schema(example = "sub")]
    pub name: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
}

impl GetRecordResponse {
    /// Build a response from a [`Record`], rendering owner/value as display names within `zone_name`.
    pub fn from_record_and_zone_name(record: &Record, zone_name: &ZoneName) -> Self {
        GetRecordResponse {
            id: Some(record.id),
            name: record.name.to_fqdn(zone_name),
            record_type: record.record_type.to_string(),
            value: display_record_value_request(&record.value, &record.record_type),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: Some(zone_name.to_fqdn()),
        }
    }

    pub fn from_record_with_zone(record: &RecordWithZone) -> Self {
        Self::from_record_and_zone_name(&record.record(), &record.zone_name)
    }
}

/// A single record wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct RecordResponse {
    pub record: GetRecordResponse,
}

/// Response for a bulk insert: the count inserted and the created records. On a
/// dry run `records` holds the validated would-be records (with placeholder
/// IDs) and nothing is inserted.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct BulkRecordsResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 3)]
    pub inserted: usize,
    pub records: Vec<GetRecordResponse>,
    /// The insert as a record diff (all additions), for previewing the change.
    pub diff: RecordDiff,
}
