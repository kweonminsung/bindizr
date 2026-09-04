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
    pub created_at: DateTime<Utc>,
}

impl GetTokenGrantResponse {
    pub fn from_grant(grant: &TokenGrantWithNames) -> Self {
        GetTokenGrantResponse {
            id: grant.grant.id,
            api_token: grant.api_token_name.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.grant.record_name_pattern.clone(),
            record_types: grant.grant.record_types.clone(),
            created_at: grant.grant.created_at,
        }
    }
}

/// A single token grant wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct TokenGrantResponse {
    pub token_grant: GetTokenGrantResponse,
}

/// Grants of one token, or every grant that applies to one zone.
#[derive(Serialize, Debug, ToSchema)]
pub struct TokenGrantListResponse {
    pub token_grants: Vec<GetTokenGrantResponse>,
}
