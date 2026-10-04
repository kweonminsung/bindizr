//! TSIG key payloads.

use bindizr_core::model::tsig_key::{TsigAlgorithm, TsigKeyId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::model::tsig_key::TsigKey;

/// Request body for creating a TSIG key. Omitting `secret` generates one.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTsigKeyRequest {
    #[schema(example = "update-key")]
    pub name: String,
    /// Defaults to `hmac-sha256`; also accepts `hmac-sha384` and `hmac-sha512`.
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

/// Query parameters of the TSIG keys listing: one role's, or every one.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct TsigKeyFilter {
    /// Only the TSIG keys authenticating into this role.
    #[schema(example = "secondaries")]
    pub role_name: Option<String>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// API representation of a TSIG key; never carries the secret.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetTsigKeyResponse {
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

impl GetTsigKeyResponse {
    /// Build a TSIG key response with its role's name, without the secret.
    pub(crate) fn from_key(key: &TsigKey, role_name: &str) -> Self {
        GetTsigKeyResponse {
            id: key.id,
            name: key.name.clone(),
            algorithm: key.algorithm,
            role_name: role_name.to_string(),
            created_at: key.created_at,
        }
    }
}

/// A key with its secret: the create and get responses.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct TsigKeyResponse {
    pub tsig_key: GetTsigKeyResponse,
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: String,
}

impl TsigKeyResponse {
    /// Build a TSIG key response, with its secret and its role's name.
    pub(crate) fn from_key(key: &TsigKey, role_name: &str) -> Self {
        TsigKeyResponse {
            tsig_key: GetTsigKeyResponse::from_key(key, role_name),
            secret: key.secret.clone(),
        }
    }
}
