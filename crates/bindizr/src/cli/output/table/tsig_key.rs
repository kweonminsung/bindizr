use std::fmt;

use bindizr_core::model::tsig_key::TsigKeyId;
use bindizr_service::types::{SingleTsigKeyResponse, TsigKeyResponse};
use tabled::Tabled;

use crate::cli::output::display;

/// SECRET is filled from the create and get responses; a listing carries none.
#[derive(Clone, PartialEq, Eq, Tabled)]
pub(crate) struct TsigKeyRow {
    #[tabled(rename = "ID")]
    pub(crate) id: TsigKeyId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "ALGORITHM")]
    pub(crate) algorithm: String,
    #[tabled(rename = "SECRET")]
    pub(crate) secret: String,
    #[tabled(rename = "ROLE")]
    pub(crate) role_name: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl fmt::Debug for TsigKeyRow {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKeyRow")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .field("role_name", &self.role_name)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<&TsigKeyResponse> for TsigKeyRow {
    /// Build a CLI table row from the TSIG key response.
    fn from(tsig_key: &TsigKeyResponse) -> Self {
        Self {
            id: tsig_key.id,
            name: tsig_key.name.clone(),
            algorithm: tsig_key.algorithm.to_string(),
            secret: display::MISSING_CELL.to_string(),
            role_name: tsig_key.role_name.clone(),
            created_at: display::display_time(tsig_key.created_at),
        }
    }
}

impl From<&SingleTsigKeyResponse> for TsigKeyRow {
    /// Build a CLI table row from the TSIG key response.
    fn from(response: &SingleTsigKeyResponse) -> Self {
        Self {
            secret: response.secret.clone(),
            ..Self::from(&response.tsig_key)
        }
    }
}
