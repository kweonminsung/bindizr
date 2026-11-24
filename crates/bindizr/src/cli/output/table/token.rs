use std::fmt;

use bindizr_core::model::api_token::ApiTokenId;
use bindizr_service::types::{ApiTokenResponse, CreateApiTokenResponse};
use tabled::Tabled;

use crate::cli::output::display;

/// SECRET is filled only from a create response, the one time the secret is shown.
#[derive(Clone, PartialEq, Eq, Tabled)]
pub(crate) struct ApiTokenRow {
    #[tabled(rename = "ID")]
    pub(crate) id: ApiTokenId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "SECRET")]
    pub(crate) secret: String,
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

impl fmt::Debug for ApiTokenRow {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiTokenRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .field("role_name", &self.role_name)
            .field("description", &self.description)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

impl From<&ApiTokenResponse> for ApiTokenRow {
    /// Build a CLI table row from the token response.
    fn from(token: &ApiTokenResponse) -> Self {
        Self {
            id: token.id,
            name: token.name.clone(),
            secret: display::MISSING_CELL.to_string(),
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

impl From<&CreateApiTokenResponse> for ApiTokenRow {
    /// Build a CLI table row from the newly created token.
    fn from(created: &CreateApiTokenResponse) -> Self {
        Self {
            secret: created.secret.clone(),
            ..Self::from(&created.token)
        }
    }
}
