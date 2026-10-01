//! API token payloads.

use bindizr_core::model::api_token::TokenId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::api_token::ApiToken;

/// Request body for creating an API token.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
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
    /// The role whose grants decide what the token may do.
    #[schema(example = "external-dns-prod")]
    pub role_name: String,
}

/// API representation of an API token; never carries the secret.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetTokenResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: TokenId,
    #[schema(example = "external-dns")]
    pub name: String,
    pub description: Option<String>,
    /// The role the token authenticates into.
    #[schema(example = "external-dns-prod")]
    pub role_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl GetTokenResponse {
    /// Build a token response with its role's name, without exposing its stored hash.
    pub(crate) fn from_token(token: &ApiToken, role_name: &str) -> Self {
        GetTokenResponse {
            id: token.id,
            name: token.name.clone(),
            description: token.description.clone(),
            role_name: role_name.to_string(),
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
        }
    }
}

/// One token without its secret: the self lookup.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct TokenResponse {
    pub token: GetTokenResponse,
}

/// The create response: the token and its secret, the one time it is shown.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct CreatedTokenResponse {
    pub token: GetTokenResponse,
    #[schema(example = "k7Qm2xLp9vRt4wYz8bNc1dFg6hJs3aEu")]
    pub secret: String,
}
