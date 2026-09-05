//! API token payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::api_token::ApiToken;

/// Request body for creating an API token.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateTokenRequest {
    #[schema(example = "external-dns")]
    pub name: String,
    #[schema(example = "ExternalDNS in the prod cluster")]
    pub description: Option<String>,
    /// Days until expiry; omit for a token that never expires.
    #[schema(example = 90)]
    pub expires_in_days: Option<i64>,
    /// Make the token global: it may manage every zone and the zone plane.
    /// Fixed at creation.
    #[serde(default)]
    #[schema(example = false)]
    pub global: bool,
}

/// API representation of an API token. `token` carries the raw secret and is
/// only present in the create response — the one time it is shown.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTokenResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "external-dns")]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "k7Qm2xLp9vRt4wYz8bNc1dFg6hJs3aEu")]
    pub token: Option<String>,
    pub description: Option<String>,
    /// Whether the token may manage every zone and the zone plane.
    #[schema(example = false)]
    pub global: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl GetTokenResponse {
    /// An empty `token` is treated as already-cleared and omitted.
    pub fn from_token(token: &ApiToken) -> Self {
        GetTokenResponse {
            id: token.id,
            name: token.name.clone(),
            token: Some(token.token.clone()).filter(|secret| !secret.is_empty()),
            description: token.description.clone(),
            global: token.is_global,
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// A single API token wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct TokenResponse {
    pub token: GetTokenResponse,
}

/// List of API tokens (secrets omitted).
#[derive(Serialize, Debug, ToSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<GetTokenResponse>,
}
