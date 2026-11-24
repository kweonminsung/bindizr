use std::fmt;

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::model::role::RoleId;

id_newtype!(
    /// The id of an API token row.
    TokenId
);

/// An API authentication token and its metadata.
#[derive(Clone, PartialEq, Eq, FromRow)]
pub struct ApiToken {
    pub id: TokenId,
    /// Unique human-facing identifier; CLI and API reference tokens by name.
    pub name: String,
    pub token: String,
    pub description: Option<String>,
    /// The role whose grants decide what the token may do; the token itself carries no rights.
    pub role_id: RoleId,
    pub created_at: DateTime<Utc>,
    /// `None` means the token never expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// `None` until the token is first used.
    pub last_used_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for ApiToken {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiToken")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("token", &"<redacted>")
            .field("description", &self.description)
            .field("role_id", &self.role_id)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

impl ApiToken {
    /// Return whether the token has expired by `now`; one without an expiry never does.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

/// Token metadata joined with its role name, without the authentication hash.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ApiTokenMetadata {
    pub id: TokenId,
    pub name: String,
    pub description: Option<String>,
    pub role_name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the stored token verifier is absent from Debug output.
    #[test]
    fn api_token_debug_masks_verifier() {
        let token = ApiToken {
            id: TokenId::from(1),
            name: "test".to_string(),
            token: "fixture-token-verifier".to_string(),
            description: None,
            role_id: RoleId::from(1),
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
        };

        for debug in [format!("{token:?}"), format!("{:#?}", Some(&token))] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("fixture-token-verifier"));
        }
    }
}
