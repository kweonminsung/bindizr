//! TSIG key and TSIG grant payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::{tsig_grant::TsigGrantWithNames, tsig_key::TsigKey};

/// Request body for creating a TSIG key. Omitting `secret` generates one.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateTsigKeyRequest {
    #[schema(example = "update-key")]
    pub name: String,
    /// Defaults to `hmac-sha256`; also accepts `hmac-sha384` and `hmac-sha512`.
    #[schema(example = "hmac-sha256")]
    pub algorithm: Option<String>,
    /// Existing base64 secret to import; omit to generate a random one.
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: Option<String>,
    /// Make the key global: it may update every zone (all names, all types)
    /// without any grant. Fixed at creation.
    #[serde(default)]
    #[schema(example = false)]
    pub global: bool,
}

/// API representation of a TSIG key; never carries the secret.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTsigKeyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "update-key")]
    pub name: String,
    #[schema(example = "hmac-sha256")]
    pub algorithm: String,
    /// Whether the key may update every zone without any grant.
    #[schema(example = false)]
    pub global: bool,
    pub created_at: DateTime<Utc>,
}

impl GetTsigKeyResponse {
    pub fn from_key(key: &TsigKey) -> Self {
        GetTsigKeyResponse {
            id: key.id,
            name: key.name.clone(),
            algorithm: key.algorithm.to_string(),
            global: key.is_global,
            created_at: key.created_at,
        }
    }
}

/// Request body for granting a TSIG key nsupdate rights in a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateTsigGrantRequest {
    /// Name of an existing zone.
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative name.
    /// Defaults to `*`.
    #[schema(example = "*.dyn")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Defaults to `*`.
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: Option<String>,
}

/// API representation of a TSIG grant.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTsigGrantResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "update-key")]
    pub tsig_key: String,
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(example = "*.dyn")]
    pub record_name_pattern: String,
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

impl GetTsigGrantResponse {
    pub fn from_grant(grant: &TsigGrantWithNames) -> Self {
        GetTsigGrantResponse {
            id: grant.grant.id,
            tsig_key: grant.tsig_key_name.clone(),
            zone_name: grant.zone_name.clone(),
            record_name_pattern: grant.grant.record_name_pattern.clone(),
            record_types: grant.grant.record_types.clone(),
            created_at: grant.grant.created_at,
        }
    }
}

/// A key with its secret: the create and get responses.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct TsigKeyResponse {
    pub tsig_key: GetTsigKeyResponse,
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: String,
}

impl TsigKeyResponse {
    pub fn from_key(key: &TsigKey) -> Self {
        TsigKeyResponse {
            tsig_key: GetTsigKeyResponse::from_key(key),
            secret: key.secret.clone(),
        }
    }
}

/// List of TSIG keys (secrets omitted).
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigKeyListResponse {
    pub tsig_keys: Vec<GetTsigKeyResponse>,
}

/// A single TSIG grant wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigGrantResponse {
    pub tsig_grant: GetTsigGrantResponse,
}

/// Grants of one key, or every grant that applies to one zone.
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigGrantListResponse {
    pub tsig_grants: Vec<GetTsigGrantResponse>,
}
