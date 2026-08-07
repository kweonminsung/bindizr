use bindizr_core::dns::{
    name::to_fqdn_lowercase,
    record::{
        display_record_owner_name, display_record_value,
        value::{SoaMailbox, TxtContent, TxtRdata},
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    error::ServiceError,
    model::{
        record::{Record, RecordType, RecordWithZone},
        tsig_key::TsigKey,
        zone::Zone,
        zone_snapshot::ZoneSnapshot,
    },
    zone::{token_policy::ZoneTokenPolicyWithToken, tsig_policy::ZoneTsigPolicyWithKey},
};

/// A page of items together with its pagination metadata.
#[derive(Serialize, Debug, ToSchema)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: Pagination,
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
    #[schema(example = 42)]
    pub serial: i32,
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
    pub fn from_zone(zone: &Zone) -> Self {
        GetZoneResponse {
            id: zone.id,
            name: zone.name.clone(),
            primary_ns: zone.primary_ns.clone(),
            admin_email: zone.admin_email.clone(),
            ttl: zone.ttl,
            serial: zone.serial,
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
        }
    }
}

/// Request body for creating a TSIG key. Omitting `secret` generates one.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateTsigKeyRequest {
    #[schema(example = "update-key")]
    pub name: String,
    /// Defaults to `hmac-sha256`; also accepts `hmac-sha384` and `hmac-sha512`.
    #[schema(example = "hmac-sha256")]
    pub algorithm: Option<String>,
    /// Existing base64 secret to import; omit to generate a random one.
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: Option<String>,
    /// Make the key global: it may update every zone (all names, all types)
    /// without any policy. Fixed at creation.
    #[serde(default)]
    #[schema(example = false)]
    pub global: bool,
}

/// API representation of a TSIG key. `secret` is only present on create and
/// single-key reads; list responses omit it.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTsigKeyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "update-key")]
    pub name: String,
    #[schema(example = "hmac-sha256")]
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: Option<String>,
    /// Whether the key may update every zone without any policy.
    #[schema(example = false)]
    pub global: bool,
    pub created_at: DateTime<Utc>,
}

impl GetTsigKeyResponse {
    /// An empty secret is treated as already-cleared and omitted.
    pub fn from_key(key: &TsigKey) -> Self {
        GetTsigKeyResponse {
            id: key.id,
            name: key.name.clone(),
            algorithm: key.algorithm.to_string(),
            secret: Some(key.secret.clone()).filter(|secret| !secret.is_empty()),
            global: key.is_global,
            created_at: key.created_at,
        }
    }
}

/// Request body for granting a TSIG key nsupdate rights in a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateZoneTsigPolicyRequest {
    /// Name of an existing TSIG key.
    #[schema(example = "update-key")]
    pub tsig_key: String,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative name.
    /// Defaults to `*`.
    #[schema(example = "*.dyn")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Defaults to `*`.
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: Option<String>,
}

/// API representation of a zone TSIG policy.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetZoneTsigPolicyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "update-key")]
    pub tsig_key: String,
    #[schema(example = "*.dyn")]
    pub record_name_pattern: String,
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

impl GetZoneTsigPolicyResponse {
    pub fn from_policy(policy: &ZoneTsigPolicyWithKey) -> Self {
        GetZoneTsigPolicyResponse {
            id: policy.policy.id,
            tsig_key: policy.tsig_key_name.clone(),
            record_name_pattern: policy.policy.record_name_pattern.clone(),
            record_types: policy.policy.record_types.clone(),
            created_at: policy.policy.created_at,
        }
    }
}

/// Request body for granting an API token record rights in a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateZoneTokenPolicyRequest {
    /// Name of an existing non-global API token.
    #[schema(example = "external-dns")]
    pub api_token: String,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative name.
    /// Defaults to `*`.
    #[schema(example = "*.dyn")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Defaults to `*`.
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: Option<String>,
}

/// API representation of a zone token policy.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetZoneTokenPolicyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "external-dns")]
    pub api_token: String,
    #[schema(example = "*.dyn")]
    pub record_name_pattern: String,
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

impl GetZoneTokenPolicyResponse {
    pub fn from_policy(policy: &ZoneTokenPolicyWithToken) -> Self {
        GetZoneTokenPolicyResponse {
            id: policy.policy.id,
            api_token: policy.api_token_name.clone(),
            record_name_pattern: policy.policy.record_name_pattern.clone(),
            record_types: policy.policy.record_types.clone(),
            created_at: policy.policy.created_at,
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
    pub ttl: i32,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = 1)]
    pub zone_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
}
impl GetRecordResponse {
    /// Build a response from a [`Record`], rendering owner/value as display names within `zone_name`.
    pub fn from_record_and_zone_name(record: &Record, zone_name: &str) -> Self {
        GetRecordResponse {
            id: record.id,
            name: display_record_owner_name(&record.name, zone_name),
            record_type: record.record_type.to_string(),
            value: display_record_value_request(&record.value, &record.record_type),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: Some(to_fqdn_lowercase(zone_name)),
        }
    }

    pub fn from_record_with_zone(record: &RecordWithZone) -> Self {
        Self::from_record_and_zone_name(&record.record(), &record.zone_name)
    }
}

fn decode_txt_value_request(value: &str) -> RecordValueRequest {
    match TxtRdata::from_encoded(value).and_then(|rdata| rdata.to_content()) {
        Some(TxtContent::Single(value)) => RecordValueRequest::String(value),
        Some(TxtContent::Segments(segments)) => RecordValueRequest::Segments(segments),
        None => RecordValueRequest::String(value.to_string()),
    }
}

/// A stored value as the record APIs display it: TXT decoded to string/segments,
/// other types rendered with trailing-dot FQDNs. Priority stays a separate field.
pub(crate) fn display_record_value_request(
    value: &str,
    record_type: &RecordType,
) -> RecordValueRequest {
    if *record_type == RecordType::TXT {
        decode_txt_value_request(value)
    } else {
        RecordValueRequest::String(display_record_value(value, record_type))
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
                Ok(TxtRdata::from_string(value).into_encoded())
            }
            (RecordType::TXT, RecordValueRequest::Segments(segments)) => {
                TxtRdata::from_segments(segments.iter().map(String::as_str))
                    .map(TxtRdata::into_encoded)
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
    /// Starting serial, auto-generated if not provided. Must be 1-2137483647 so the counter keeps room to advance, and can only be set at creation.
    #[schema(example = 42)]
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
#[derive(Deserialize, Debug, ToSchema)]
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
#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateBulkRecordsRequest {
    pub records: Vec<RecordItem>,
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
    /// The insert as a record diff (all additions), for previewing the change.
    pub diff: RecordDiff,
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
    /// The reconcile as a record diff, for previewing the change.
    pub diff: RecordDiff,
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
    #[schema(example = 42)]
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

/// A partial record update; an omitted field keeps the current value. Merged
/// inside the update transaction so a concurrent write is not lost.
#[derive(Deserialize, Debug, Default)]
pub struct UpdateRecordPatch {
    pub name: Option<String>,
    pub record_type: Option<String>,
    pub value: Option<RecordValueRequest>,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}

/// A partial zone update; an omitted field keeps the current value, merged
/// inside the update transaction. `serial` is carried only to be rejected.
#[derive(Deserialize, Debug, Default)]
pub struct UpdateZonePatch {
    pub new_name: Option<String>,
    pub primary_ns: Option<String>,
    pub admin_email: Option<String>,
    pub ttl: Option<i32>,
    pub refresh: Option<i32>,
    pub retry: Option<i32>,
    pub expire: Option<i32>,
    pub minimum_ttl: Option<i32>,
    pub serial: Option<i32>,
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

/// A single TSIG key wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigKeyResponse {
    pub tsig_key: GetTsigKeyResponse,
}

/// List of TSIG keys (secrets omitted).
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigKeyListResponse {
    pub tsig_keys: Vec<GetTsigKeyResponse>,
}

/// A single zone TSIG policy wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneTsigPolicyResponse {
    pub tsig_policy: GetZoneTsigPolicyResponse,
}

/// List of a zone's TSIG policies.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneTsigPolicyListResponse {
    pub tsig_policies: Vec<GetZoneTsigPolicyResponse>,
}

/// A single zone token policy wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneTokenPolicyResponse {
    pub token_policy: GetZoneTokenPolicyResponse,
}

/// List of a zone's token policies.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneTokenPolicyListResponse {
    pub token_policies: Vec<GetZoneTokenPolicyResponse>,
}

/// A single record wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct RecordResponse {
    pub record: GetRecordResponse,
}

/// One RRset (owner name and type) exchanged with the ExternalDNS API. Names
/// are absolute; TXT values are quoted presentation strings.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ExternalDnsRrset {
    #[schema(example = "app.example.com")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    /// Optional on writes; an omitted or zero TTL resolves to the zone TTL.
    #[schema(example = 300)]
    pub ttl: Option<i32>,
    #[schema(example = json!(["192.0.2.10"]))]
    pub values: Vec<String>,
}

/// An RRset replacement: `old` values are removed and `new` written in place.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ExternalDnsRrsetUpdate {
    pub old: ExternalDnsRrset,
    pub new: ExternalDnsRrset,
}

/// Request body for applying an ExternalDNS change set atomically.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ExternalDnsChangesRequest {
    #[serde(default)]
    pub creates: Vec<ExternalDnsRrset>,
    #[serde(default)]
    pub updates: Vec<ExternalDnsRrsetUpdate>,
    #[serde(default)]
    pub deletes: Vec<ExternalDnsRrset>,
}

/// Summary of an applied ExternalDNS change set.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsChangesResponse {
    /// Zones whose serial advanced; empty when the request was a no-op.
    #[schema(example = json!(["example.com"]))]
    pub changed_zones: Vec<String>,
    #[schema(example = 2)]
    pub records_added: u32,
    #[schema(example = 1)]
    pub records_deleted: u32,
}

/// Zones the ExternalDNS caller may manage under the current policy.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsZonesResponse {
    #[schema(example = json!(["example.com"]))]
    pub zones: Vec<String>,
}

/// One record row managed through the ExternalDNS API: absolute owner name
/// and the value in presentation form (TXT quoted).
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsRecordItem {
    #[schema(example = "app.example.com")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    #[schema(example = 300)]
    pub ttl: i32,
    #[schema(example = "192.0.2.10")]
    pub value: String,
}

/// Records of every ExternalDNS-managed zone, deterministically ordered.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsRecordsResponse {
    pub records: Vec<ExternalDnsRecordItem>,
}

/// Generic success message response.
#[derive(Serialize, Debug, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Deleted successfully")]
    pub message: String,
}

/// Health probe response.
#[derive(Serialize, Debug, ToSchema)]
pub struct HealthResponse {
    #[schema(example = "healthy")]
    pub status: String,
}

/// One entry of a zone's serial history, with SOA metadata in API form
/// (`admin_email` converted back from SOA mailbox form).
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneSnapshotResponse {
    #[schema(example = 7)]
    pub serial: i32,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 7200)]
    pub refresh: i32,
    #[schema(example = 3600)]
    pub retry: i32,
    #[schema(example = 604800)]
    pub expire: i32,
    #[schema(example = 3600)]
    pub minimum_ttl: i32,
    pub created_at: DateTime<Utc>,
}

impl ZoneSnapshotResponse {
    pub fn from_snapshot(snapshot: &ZoneSnapshot) -> Result<Self, ServiceError> {
        let admin_email = SoaMailbox::from_encoded(&snapshot.admin_email)
            .to_email()
            .map_err(|e| {
                ServiceError::internal(format!("Failed to decode snapshot admin email: {}", e))
            })?;
        Ok(ZoneSnapshotResponse {
            serial: snapshot.serial,
            primary_ns: snapshot.primary_ns.clone(),
            admin_email,
            ttl: snapshot.ttl,
            refresh: snapshot.refresh,
            retry: snapshot.retry,
            expire: snapshot.expire,
            minimum_ttl: snapshot.minimum_ttl,
            created_at: snapshot.created_at,
        })
    }
}

/// A record reconstructed from the zone's change history; unlike stored
/// records it has no database id.
#[derive(Serialize, Debug, ToSchema)]
pub struct SnapshotRecordResponse {
    #[schema(example = "www")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// One snapshot plus the reconstructed record set at that serial.
#[derive(Serialize, Debug, ToSchema)]
pub struct SnapshotDetailResponse {
    pub snapshot: ZoneSnapshotResponse,
    pub records: Vec<SnapshotRecordResponse>,
}

/// One record on one side of a diff. Rendering (zone-file rdata, priority
/// placement) is left to the client; the value is in display form.
#[derive(Clone, Serialize, Debug, ToSchema)]
pub struct RecordDiffValue {
    pub value: RecordValueRequest,
    #[schema(example = 300)]
    pub ttl: i32,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

/// One RRset (owner name + type) whose records differ, with the records present
/// on each side. `from` is empty for `added`, `to` for `removed`.
#[derive(Serialize, Debug, ToSchema)]
pub struct RecordDiffEntry {
    /// `added`, `removed`, or `changed`.
    #[schema(example = "changed")]
    pub change: String,
    #[schema(example = "www.example.com.")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub from: Vec<RecordDiffValue>,
    pub to: Vec<RecordDiffValue>,
}

/// How many RRsets were added, removed, and changed.
#[derive(Default, Serialize, Debug, ToSchema)]
pub struct RecordDiffSummary {
    #[schema(example = 1)]
    pub added: usize,
    #[schema(example = 1)]
    pub removed: usize,
    #[schema(example = 1)]
    pub changed: usize,
}

/// A record-level difference between two record sets, RRset by RRset. Empty on
/// a real apply, which does not need it; populated only for a dry-run preview.
#[derive(Default, Serialize, Debug, ToSchema)]
pub struct RecordDiff {
    pub entries: Vec<RecordDiffEntry>,
    pub summary: RecordDiffSummary,
}

/// The difference between two of a zone's serials.
#[derive(Serialize, Debug, ToSchema)]
pub struct SnapshotDiffResponse {
    #[schema(example = 41)]
    pub from_serial: i32,
    #[schema(example = 42)]
    pub to_serial: i32,
    pub diff: RecordDiff,
}

/// Request body for rolling a zone back to a snapshot serial.
#[derive(Deserialize, Debug, ToSchema)]
pub struct RollbackZoneRequest {
    #[schema(example = 7)]
    pub serial: i32,
    /// When true, compute and report the rollback without applying any change.
    #[serde(default, alias = "dryRun")]
    pub dry_run: bool,
}

/// Counts of what a rollback changes. TTL-only differences count as one
/// delete plus one add.
#[derive(Serialize, Debug, ToSchema)]
pub struct RollbackSummary {
    #[schema(example = 2)]
    pub records_added: usize,
    #[schema(example = 3)]
    pub records_deleted: usize,
    #[schema(example = 5)]
    pub records_unchanged: usize,
    #[schema(example = true)]
    pub soa_changed: bool,
}

/// Result of a zone rollback. The zone's state returns to `target_serial`
/// while its serial advances to `new_serial` (serials never go backward).
#[derive(Serialize, Debug, ToSchema)]
pub struct RollbackZoneResponse {
    #[schema(example = true)]
    pub applied: bool,
    #[schema(example = false)]
    pub dry_run: bool,
    #[schema(example = 7)]
    pub target_serial: i32,
    #[schema(example = 13)]
    pub new_serial: i32,
    pub summary: RollbackSummary,
}

/// Sync state of one configured secondary for a zone.
#[derive(Serialize, Debug, ToSchema)]
pub struct SecondaryStatusResponse {
    #[schema(example = "10.0.1.10:53")]
    pub address: String,
    /// `in_sync` | `lagging` | `ahead` | `unreachable`
    #[schema(example = "in_sync")]
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 42)]
    pub visible_serial: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A zone's serial and the sync state of every configured secondary, probed
/// live via SOA queries.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneStatusResponse {
    #[schema(example = "example.com")]
    pub zone: String,
    #[schema(example = 42)]
    pub serial: i32,
    pub secondaries: Vec<SecondaryStatusResponse>,
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
    pub fn new(err: &ServiceError) -> Self {
        ErrorResponse {
            error: err.message.clone(),
            code: err.code.as_str().to_string(),
        }
    }
}
