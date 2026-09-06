//! ExternalDNS webhook payloads, mirroring the provider protocol.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One record of the ExternalDNS API: every value of one name and type. Names
/// are absolute; TXT values are quoted presentation strings.
#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ExternalDnsRecord {
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

/// A record replacement: `old` values are removed and `new` written in place.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ExternalDnsRecordUpdate {
    pub old: ExternalDnsRecord,
    pub new: ExternalDnsRecord,
}

/// Request body for canonicalizing desired records without applying them.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ExternalDnsAdjustRequest {
    pub records: Vec<ExternalDnsRecord>,
}

/// The request's records in the canonical form applying them would store.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsAdjustResponse {
    pub records: Vec<ExternalDnsRecord>,
}

/// Request body for applying an ExternalDNS change set atomically.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ExternalDnsChangesRequest {
    #[serde(default)]
    pub creates: Vec<ExternalDnsRecord>,
    #[serde(default)]
    pub updates: Vec<ExternalDnsRecordUpdate>,
    #[serde(default)]
    pub deletes: Vec<ExternalDnsRecord>,
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

/// Zones the ExternalDNS caller may manage under its grants.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsZonesResponse {
    #[schema(example = json!(["example.com"]))]
    pub zones: Vec<String>,
}

/// Records of every ExternalDNS-managed zone, one per name and type, in a
/// deterministic order.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsRecordsResponse {
    pub records: Vec<ExternalDnsRecord>,
}
