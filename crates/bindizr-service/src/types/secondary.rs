//! Secondary server payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{model::secondary::Secondary, types::SecondaryStatusResponse};

/// Request body for registering a secondary.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSecondaryRequest {
    /// A plain identifier, since it travels in URL paths.
    #[schema(example = "ns2")]
    pub name: String,
    /// `host[:port]`, port 53 when left out; a hostname is resolved when used.
    #[schema(example = "ns2.example.net:53")]
    pub address: String,
    /// TSIG key to sign NOTIFY to this server with; omitted sends it unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "notify-key")]
    pub notify_key: Option<String>,
}

/// Request body for changing a secondary; an omitted field keeps its value.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSecondaryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "192.0.2.7:53")]
    pub address: Option<String>,
    /// `false` stops NOTIFY, unsigned transfers, and probes without
    /// forgetting the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = true)]
    pub enabled: Option<bool>,
    /// TSIG key to sign NOTIFY with; empty sends it unsigned again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "notify-key")]
    pub notify_key: Option<String>,
}

/// API representation of a secondary.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetSecondaryResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "ns2")]
    pub name: String,
    #[schema(example = "ns2.example.net:53")]
    pub address: String,
    #[schema(example = true)]
    pub enabled: bool,
    /// The TSIG key NOTIFY to this server is signed with, if any.
    #[schema(example = "notify-key")]
    pub notify_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl GetSecondaryResponse {
    /// Build the API representation from a stored secondary and its NOTIFY
    /// key's name.
    pub fn from_secondary(secondary: &Secondary, notify_key: Option<&str>) -> Self {
        GetSecondaryResponse {
            id: secondary.id,
            name: secondary.name.clone(),
            address: secondary.address.clone(),
            enabled: secondary.enabled,
            notify_key: notify_key.map(str::to_string),
            created_at: secondary.created_at,
        }
    }
}

/// A secondary wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SecondaryResponse {
    pub secondary: GetSecondaryResponse,
}

/// One NOTIFY sent to a resolved address during a check.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct NotifyCheckResponse {
    #[schema(example = "10.0.0.14:53")]
    pub address: String,
    #[schema(example = true)]
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What a secondary answered when checked: where its address resolves, the
/// catalog zone serial it serves against Bindizr's, and whether it accepted
/// a NOTIFY.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SecondaryCheckResponse {
    pub secondary: GetSecondaryResponse,
    /// Socket addresses the registered `host[:port]` resolves to now.
    #[schema(example = json!(["10.0.0.14:53"]))]
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_error: Option<String>,
    /// The catalog zone the secondary was asked for.
    #[schema(example = "catalog.bindizr")]
    pub catalog_zone: String,
    /// The serial Bindizr's own listener serves the catalog zone at; absent
    /// with `listener_error`, and `catalog` is then `reachable` at best.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = 42)]
    pub catalog_serial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener_error: Option<String>,
    /// The secondary's catalog probe, classified against `catalog_serial`.
    pub catalog: SecondaryStatusResponse,
    /// The NOTIFY sent for the catalog zone, one per resolved address.
    pub notifies: Vec<NotifyCheckResponse>,
}

impl SecondaryCheckResponse {
    /// Whether every part of the check passed: resolved, in sync, and every
    /// NOTIFY accepted.
    pub fn is_healthy(&self) -> bool {
        self.resolve_error.is_none()
            && self.catalog.is_in_sync()
            && self.notifies.iter().all(|notify| notify.accepted)
    }
}
