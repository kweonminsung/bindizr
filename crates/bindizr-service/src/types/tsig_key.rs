//! TSIG key payloads.

use std::fmt;

use bindizr_core::model::tsig_key::{TsigAlgorithm, TsigKey, TsigKeyId, TsigKeyMetadata};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Request body for creating a TSIG key. Omitting `secret` generates one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTsigKeyRequest {
    #[schema(example = "update-key")]
    pub name: String,
    /// Defaults to `hmac-sha256`; also accepts `hmac-sha384`, `hmac-sha512`, and legacy `hmac-sha1` (RFC 8945).
    #[schema(example = "hmac-sha256")]
    pub algorithm: Option<String>,
    /// Existing base64 secret to import; omit to generate a random one.
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: Option<String>,
    /// The role whose grants decide what the key may sign; a NOTIFY-only key
    /// may name one without grants.
    #[schema(example = "rfc2136-legacy")]
    pub role_name: String,
}

impl fmt::Debug for CreateTsigKeyRequest {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateTsigKeyRequest")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("secret", &"<redacted>")
            .field("role_name", &self.role_name)
            .finish()
    }
}

/// Query parameters of the TSIG keys listing: one role's, or every one.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct TsigKeyFilter {
    /// Only the TSIG keys authenticating into this role.
    pub role_name: Option<String>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// API representation of a TSIG key; never carries the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TsigKeyResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: TsigKeyId,
    #[schema(example = "update-key")]
    pub name: String,
    #[schema(example = "hmac-sha256")]
    pub algorithm: TsigAlgorithm,
    /// The role the key authenticates into.
    #[schema(example = "rfc2136-legacy")]
    pub role_name: String,
    pub created_at: DateTime<Utc>,
}

impl TsigKeyResponse {
    /// Build TSIG key information with its role name, without the secret.
    pub(crate) fn from_tsig_key(tsig_key: &TsigKey, role_name: &str) -> Self {
        Self {
            id: tsig_key.id,
            name: tsig_key.name.clone(),
            algorithm: tsig_key.algorithm,
            role_name: role_name.to_string(),
            created_at: tsig_key.created_at,
        }
    }
}

/// A key with its secret: the create and get responses.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SingleTsigKeyResponse {
    pub tsig_key: TsigKeyResponse,
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: String,
}

impl fmt::Debug for SingleTsigKeyResponse {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleTsigKeyResponse")
            .field("tsig_key", &self.tsig_key)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl From<&TsigKeyMetadata> for TsigKeyResponse {
    /// Build the response from metadata that carries no credential material.
    fn from(tsig_key: &TsigKeyMetadata) -> Self {
        Self {
            id: tsig_key.id,
            name: tsig_key.name.clone(),
            algorithm: tsig_key.algorithm,
            role_name: tsig_key.role_name.clone(),
            created_at: tsig_key.created_at,
        }
    }
}
