//! Token grant payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::token_grant::TokenGrantWithNames;

/// Request body for granting an API token record rights in a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateTokenGrantRequest {
    /// Name of an existing zone.
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative name.
    /// Defaults to `*`.
    #[schema(example = "*.dyn")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Defaults to `*`.
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: Option<String>,
    /// Whether the grant carries write rights. A read-only grant still makes
    /// the zone visible, narrowed the same way. Defaults to true.
    #[serde(default = "default_can_write")]
    #[schema(example = true)]
    pub can_write: bool,
}

/// Enable write access when a new grant omits the permission flag.
fn default_can_write() -> bool {
    true
}

/// API representation of a token grant.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTokenGrantResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "external-dns")]
    pub api_token: String,
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(example = "*.dyn")]
    pub record_name_pattern: String,
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: String,
    #[schema(example = true)]
    pub can_write: bool,
    pub created_at: DateTime<Utc>,
}

impl GetTokenGrantResponse {
    /// Build a token-grant response with its token and zone names.
    pub fn from_grant(grant: &TokenGrantWithNames) -> Self {
        GetTokenGrantResponse {
            id: grant.grant.id,
            api_token: grant.api_token_name.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.grant.record_name_pattern.clone(),
            record_types: grant.grant.record_types.clone(),
            can_write: grant.grant.can_write,
            created_at: grant.grant.created_at,
        }
    }
}

/// A single token grant wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TokenGrantResponse {
    pub token_grant: GetTokenGrantResponse,
}
