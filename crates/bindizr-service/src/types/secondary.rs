//! Secondary server payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::secondary::Secondary;

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
    pub created_at: DateTime<Utc>,
}

impl GetSecondaryResponse {
    /// Build the API representation from a stored secondary.
    pub fn from_secondary(secondary: &Secondary) -> Self {
        GetSecondaryResponse {
            id: secondary.id,
            name: secondary.name.clone(),
            address: secondary.address.clone(),
            enabled: secondary.enabled,
            created_at: secondary.created_at,
        }
    }
}

/// A secondary wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SecondaryResponse {
    pub secondary: GetSecondaryResponse,
}
