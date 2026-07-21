use bindizr_core::dns::{
    name::to_fqdn_lowercase,
    record::{display_record_owner_name, display_record_value},
    txt,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::{
    record::{Record, RecordType, RecordWithZone},
    zone::Zone,
};

/// A page of items together with its pagination metadata.
#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
}

impl<T> PaginatedResponse<T> {
    /// Map each item to a new type, preserving the pagination metadata.
    pub fn map_items<U>(self, mut f: impl FnMut(T) -> U) -> PaginatedResponse<U> {
        PaginatedResponse {
            items: self.items.into_iter().map(&mut f).collect(),
            pagination: self.pagination,
        }
    }
}

/// Pagination window and total count for a list response.
#[derive(Serialize, Debug, ToSchema)]
pub struct Pagination {
    #[schema(example = 50)]
    pub limit: u32,
    #[schema(example = 0)]
    pub offset: u64,
    #[schema(example = 125)]
    pub total: u64,
}

/// API representation of a zone.
#[derive(Serialize, Debug, ToSchema)]
pub struct GetZoneResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 2025100101)]
    pub serial: Option<i32>,
    #[schema(example = 7200)]
    pub refresh: i32,
    #[schema(example = 3600)]
    pub retry: i32,
    #[schema(example = 604800)]
    pub expire: i32,
    #[schema(example = 3600)]
    pub minimum_ttl: i32,
}
impl GetZoneResponse {
    /// Build a response from a [`Zone`].
    pub fn from_zone(zone: &Zone) -> Self {
        GetZoneResponse {
            id: zone.id,
            name: zone.name.clone(),
            primary_ns: zone.primary_ns.clone(),
            admin_email: zone.admin_email.clone(),
            ttl: zone.ttl,
            serial: Some(zone.serial),
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
        }
    }
}

/// API representation of a record, optionally carrying its zone name.
#[derive(Serialize, Debug, ToSchema)]
pub struct GetRecordResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    #[schema(example = "192.168.1.100")]
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = 1)]
    pub zone_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
}
impl GetRecordResponse {
    /// Build a response from a [`Record`], leaving names in stored form and `zone_name` unset.
    pub fn from_record(record: &Record) -> Self {
        GetRecordResponse {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.to_string(),
            value: record_response_value(record, false),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: None,
        }
    }

    /// Build a response from a [`Record`], rendering owner/value as display names within `zone_name`.
    pub fn from_record_and_zone_name(record: &Record, zone_name: &str) -> Self {
        GetRecordResponse {
            id: record.id,
            name: display_record_owner_name(&record.name, zone_name),
            record_type: record.record_type.to_string(),
            value: record_response_value(record, true),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: Some(to_fqdn_lowercase(zone_name)),
        }
    }

    /// Build a response from a [`RecordWithZone`].
    pub fn from_record_with_zone(record: &RecordWithZone) -> Self {
        Self::from_record_and_zone_name(&record.record(), &record.zone_name)
    }
}

fn record_response_value(record: &Record, display_names: bool) -> RecordValueRequest {
    if record.record_type == RecordType::TXT {
        match txt::decode_raw_txt_value(&record.value) {
            Some(txt::DecodedTxtValue::String(value)) => RecordValueRequest::String(value),
            Some(txt::DecodedTxtValue::Segments(segments)) => {
                RecordValueRequest::Segments(segments)
            }
            None => RecordValueRequest::String(record.value.clone()),
        }
    } else if display_names {
        RecordValueRequest::String(display_record_value(&record.value, &record.record_type))
    } else {
        RecordValueRequest::String(record.value.clone())
    }
}

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
    /// Encode the request value into its stored form for the given record type.
    pub fn to_storage_value(&self, record_type: &RecordType) -> Result<String, String> {
        match (record_type, self) {
            (RecordType::TXT, RecordValueRequest::String(value)) => {
                Ok(txt::encode_txt_string(value))
            }
            (RecordType::TXT, RecordValueRequest::Segments(segments)) => {
                txt::encode_txt_segments(segments.iter().map(String::as_str))
            }
            (_, RecordValueRequest::String(value)) => Ok(value.clone()),
            (_, RecordValueRequest::Segments(_)) => {
                Err("array value is only supported for TXT records".to_string())
            }
        }
    }
}

/// Request body for creating or updating a zone.
#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateZoneRequest {
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    #[schema(example = 3600)]
    pub ttl: i32,
    /// Auto-generated if not provided.
    #[schema(example = 2025100101)]
    pub serial: Option<i32>,
    #[schema(example = 7200)]
    pub refresh: Option<i32>,
    #[schema(example = 3600)]
    pub retry: Option<i32>,
    #[schema(example = 604800)]
    pub expire: Option<i32>,
    #[schema(example = 3600)]
    pub minimum_ttl: Option<i32>,
}

/// Request body for creating a record in a named zone.
#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = "example.com")]
    pub zone_name: String,
}

/// A single record entry for bulk insertion. The zone is taken from the request
/// path, so unlike [`CreateRecordRequest`] it carries no `zone_name`.
#[derive(Deserialize, Debug, ToSchema)]
pub struct BulkRecordItem {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// Request body for bulk-inserting records into a zone.
#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateBulkRecordsRequest {
    pub records: Vec<BulkRecordItem>,
    /// When true, parse and validate without applying any change.
    #[serde(default, alias = "dryRun")]
    pub dry_run: bool,
}

/// Response for a bulk insert: the count inserted and the created records. On a
/// dry run `records` holds the validated would-be records (with placeholder
/// IDs) and nothing is inserted.
#[derive(Serialize, Debug, ToSchema)]
pub struct BulkRecordsResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 3)]
    pub inserted: usize,
    pub records: Vec<GetRecordResponse>,
}

/// How parsed records are reconciled with the records already in the zone.
#[derive(Clone, Copy, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Add parsed records; records already present are left untouched.
    #[default]
    Append,
    /// Replace every RRset (name + type) that appears in the file with the
    /// parsed records, leaving other RRsets untouched.
    Upsert,
    /// Replace all non-protected records in the zone with the parsed records.
    Replace,
}

/// Request body for importing a BIND zone file into a zone.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ImportZoneFileRequest {
    /// Raw BIND zone file text.
    #[schema(example = "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n")]
    pub content: String,
    #[serde(default)]
    pub mode: ImportMode,
    /// When true, parse and validate without applying any change.
    #[serde(default, alias = "dryRun")]
    pub dry_run: bool,
}

/// Result of a zone-file import, including a summary and any validation errors.
#[derive(Serialize, Debug, ToSchema)]
pub struct ImportZoneFileResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    pub summary: ImportSummary,
    /// Per-record validation errors. When non-empty nothing is applied.
    pub errors: Vec<String>,
}

/// Counts of records parsed, added, deleted, updated, unchanged, and skipped
/// during import. `updated` is a TTL-only reconcile and is never also counted
/// as `unchanged`.
#[derive(Serialize, Debug, ToSchema)]
pub struct ImportSummary {
    #[schema(example = 12)]
    pub parsed: usize,
    #[schema(example = 8)]
    pub added: usize,
    #[schema(example = 2)]
    pub deleted: usize,
    #[schema(example = 1)]
    pub updated: usize,
    #[schema(example = 2)]
    pub unchanged: usize,
    #[schema(example = 0)]
    pub skipped: usize,
}

/// Query filters and pagination for listing zones.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct GetZonesFilter {
    #[schema(example = "example.com")]
    pub name: Option<String>,
    #[schema(example = 1)]
    pub id: Option<i32>,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: Option<String>,
    #[schema(example = "admin@example.com")]
    pub admin_email: Option<String>,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 300)]
    pub min_ttl: Option<i32>,
    #[schema(example = 86400)]
    pub max_ttl: Option<i32>,
    #[schema(example = 2025100101)]
    pub serial: Option<i32>,
    #[serde(alias = "q")]
    #[schema(example = "example")]
    pub search: Option<String>,
    #[schema(example = 50)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// Query filters and pagination for listing records.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct GetRecordsFilter {
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    #[serde(alias = "zone")]
    #[schema(example = "example.com")]
    pub zone: Option<String>,
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
    #[schema(example = 50)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

impl GetRecordsFilter {
    /// Return the effective zone name, preferring `zone_name` over the `zone` alias.
    pub fn resolved_zone_name(&self) -> Option<String> {
        self.zone_name.clone().or_else(|| self.zone.clone())
    }
}

/// Request body for updating an existing record.
#[derive(Deserialize, Debug, ToSchema)]
pub struct UpdateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// Request body for triggering a NOTIFY, optionally scoped to one zone.
#[derive(Deserialize, Debug, ToSchema)]
pub struct NotifyZoneRequest {
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    #[serde(default)]
    #[schema(example = true)]
    pub force: bool,
}

/// Paginated list of zones.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneListResponse {
    pub items: Vec<GetZoneResponse>,
    pub pagination: Pagination,
}

/// A zone together with all of its records.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneDetailResponse {
    pub zone: GetZoneResponse,
    pub records: Vec<GetRecordResponse>,
}

/// A single zone wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneResponse {
    pub zone: GetZoneResponse,
}

/// Paginated list of records.
#[derive(Serialize, Debug, ToSchema)]
pub struct RecordListResponse {
    pub items: Vec<GetRecordResponse>,
    pub pagination: Pagination,
}

/// A single record wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct RecordResponse {
    pub record: GetRecordResponse,
}

/// Generic success message response.
#[derive(Serialize, Debug, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Deleted successfully")]
    pub message: String,
}

/// Generic error response: a plain description plus a machine-readable code.
#[derive(Serialize, Debug, ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "Zone with name 'example.com' not found")]
    pub error: String,
    #[schema(example = "ZONE_NOT_FOUND")]
    pub code: String,
}

impl ErrorResponse {
    pub fn new(err: &crate::error::ServiceError) -> Self {
        ErrorResponse {
            error: err.message.clone(),
            code: err.code.as_str().to_string(),
        }
    }
}
