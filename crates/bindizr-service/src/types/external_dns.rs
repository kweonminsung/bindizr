//! ExternalDNS webhook payloads, mirroring the provider protocol.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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

/// Request body for canonicalizing desired RRsets without applying them.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ExternalDnsAdjustRequest {
    pub rrsets: Vec<ExternalDnsRrset>,
}

/// The request's RRsets in the canonical form applying them would store.
#[derive(Serialize, Debug, ToSchema)]
pub struct ExternalDnsAdjustResponse {
    pub rrsets: Vec<ExternalDnsRrset>,
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
