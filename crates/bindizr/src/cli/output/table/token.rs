use std::fmt;

use bindizr_core::model::api_token::TokenId;
use bindizr_service::types::{CreateTokenResponse, TokenResponse};
use tabled::Tabled;

use crate::cli::output::display;

/// TOKEN is filled only from a create response, the one time the secret is shown.
#[derive(Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TokenRow {
    #[tabled(rename = "ID")]
    pub(crate) id: TokenId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "TOKEN")]
    pub(crate) token: String,
    #[tabled(rename = "ROLE")]
    pub(crate) role_name: String,
    #[tabled(rename = "DESCRIPTION")]
    pub(crate) description: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
    #[tabled(rename = "EXPIRES-AT")]
    pub(crate) expires_at: String,
    #[tabled(rename = "LAST-USED-AT")]
    pub(crate) last_used_at: String,
}

impl fmt::Debug for TokenRow {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("token", &"<redacted>")
            .field("role_name", &self.role_name)
            .field("description", &self.description)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

impl From<&TokenResponse> for TokenRow {
    /// Build a CLI table row from the token response.
    fn from(token: &TokenResponse) -> Self {
        Self {
            id: token.id,
            name: token.name.clone(),
            token: display::MISSING_CELL.to_string(),
            role_name: token.role_name.clone(),
            description: display::display_option(&token.description),
            created_at: display::display_time(token.created_at),
            expires_at: token
                .expires_at
                .map_or_else(|| "Never".to_string(), display::display_time),
            last_used_at: display::display_option_time(&token.last_used_at),
        }
    }
}

impl From<&CreateTokenResponse> for TokenRow {
    /// Build a CLI table row from the newly created token.
    fn from(created: &CreateTokenResponse) -> Self {
        Self {
            token: created.secret.clone(),
            ..Self::from(&created.token)
        }
    }
}
