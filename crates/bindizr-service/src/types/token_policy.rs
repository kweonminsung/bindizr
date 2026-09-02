//! Zone token policy payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::zone_token_policy::ZoneTokenPolicyWithToken;

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
