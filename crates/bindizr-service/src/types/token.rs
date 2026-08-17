//! API token payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::api_token::ApiToken;

/// API representation of an API token. `token` carries the raw secret and is
/// only present in the create response — the one time it is shown.
#[derive(Serialize, Deserialize, Debug)]
pub struct GetTokenResponse {
    pub id: i32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub description: Option<String>,
    /// Whether the token may manage every zone and the zone plane.
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
