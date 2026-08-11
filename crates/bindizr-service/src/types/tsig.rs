//! TSIG key and zone TSIG policy payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{model::tsig_key::TsigKey, zone::tsig_policy::ZoneTsigPolicyWithKey};

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
    /// without any policy. Fixed at creation.
    #[serde(default)]
    #[schema(example = false)]
    pub global: bool,
}

/// API representation of a TSIG key. `secret` is only present on create and
/// single-key reads; list responses omit it.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetTsigKeyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "update-key")]
    pub name: String,
    #[schema(example = "hmac-sha256")]
    pub algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU=")]
    pub secret: Option<String>,
    /// Whether the key may update every zone without any policy.
    #[schema(example = false)]
    pub global: bool,
    pub created_at: DateTime<Utc>,
}

impl GetTsigKeyResponse {
    /// An empty secret is treated as already-cleared and omitted.
    pub fn from_key(key: &TsigKey) -> Self {
        GetTsigKeyResponse {
            id: key.id,
            name: key.name.clone(),
            algorithm: key.algorithm.to_string(),
            secret: Some(key.secret.clone()).filter(|secret| !secret.is_empty()),
            global: key.is_global,
            created_at: key.created_at,
        }
    }
}

/// Request body for granting a TSIG key nsupdate rights in a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct CreateZoneTsigPolicyRequest {
    /// Name of an existing TSIG key.
    #[schema(example = "update-key")]
    pub tsig_key: String,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative name.
    /// Defaults to `*`.
    #[schema(example = "*.dyn")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Defaults to `*`.
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: Option<String>,
}

/// API representation of a zone TSIG policy.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetZoneTsigPolicyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "update-key")]
    pub tsig_key: String,
    #[schema(example = "*.dyn")]
    pub record_name_pattern: String,
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

impl GetZoneTsigPolicyResponse {
    pub fn from_policy(policy: &ZoneTsigPolicyWithKey) -> Self {
        GetZoneTsigPolicyResponse {
            id: policy.policy.id,
            tsig_key: policy.tsig_key_name.clone(),
            record_name_pattern: policy.policy.record_name_pattern.clone(),
            record_types: policy.policy.record_types.clone(),
            created_at: policy.policy.created_at,
        }
    }
}

/// A single TSIG key wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigKeyResponse {
    pub tsig_key: GetTsigKeyResponse,
}

/// List of TSIG keys (secrets omitted).
#[derive(Serialize, Debug, ToSchema)]
pub struct TsigKeyListResponse {
    pub tsig_keys: Vec<GetTsigKeyResponse>,
}

/// A single zone TSIG policy wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneTsigPolicyResponse {
    pub tsig_policy: GetZoneTsigPolicyResponse,
}

/// List of a zone's TSIG policies.
#[derive(Serialize, Debug, ToSchema)]
pub struct ZoneTsigPolicyListResponse {
    pub tsig_policies: Vec<GetZoneTsigPolicyResponse>,
}
