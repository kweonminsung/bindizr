//! API token payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::api_token::ApiToken;

/// Request body for creating an API token.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateTokenRequest {
    /// Letters, digits, `.`, `_`, and `-`: one URL path segment.
    #[schema(example = "external-dns")]
    pub name: String,
    /// At most 255 characters.
    #[schema(example = "ExternalDNS in the prod cluster")]
    pub description: Option<String>,
    /// Days until expiry, 1 to 36500; omit for a token that never expires.
    #[schema(example = 90)]
    pub expires_in_days: Option<i64>,
    /// Make the token global: it may manage every zone and the zone plane.
    /// Fixed at creation.
    #[serde(default)]
    #[schema(example = false)]
    pub global: bool,
}

/// API representation of an API token; never carries the secret.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTokenResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "external-dns")]
    pub name: String,
    pub description: Option<String>,
    /// Whether the token may manage every zone and the zone plane.
    #[schema(example = false)]
    pub global: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl GetTokenResponse {
    pub fn from_token(token: &ApiToken) -> Self {
        GetTokenResponse {
            id: token.id,
            name: token.name.clone(),
            description: token.description.clone(),
            global: token.is_global,
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// One token without its secret: the self lookup.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TokenResponse {
    pub token: GetTokenResponse,
}

/// The create response: the token and its secret, the one time it is shown.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreatedTokenResponse {
    pub token: GetTokenResponse,
    #[schema(example = "k7Qm2xLp9vRt4wYz8bNc1dFg6hJs3aEu")]
    pub secret: String,
}

/// List of API tokens (secrets omitted).
#[derive(Serialize, Debug, ToSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<GetTokenResponse>,
}
