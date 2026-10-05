//! DNSSEC policy payloads.

use bindizr_core::model::{
    dnssec_key::DnssecAlgorithm,
    dnssec_policy::{Days, PolicyId},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::dnssec_policy::{DnssecDenial, DnssecPolicy};

/// Request body for creating a DNSSEC policy. The key layout, algorithm,
/// and denial mode are fixed once created. Omitted fields use the built-in
/// defaults, independent of edits to the policy named `default`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateDnssecPolicyRequest {
    #[schema(example = "strict")]
    pub name: String,
    /// Defaults to `ecdsap256sha256`; also accepts `ecdsap384sha384`,
    /// `ed25519`, `ed448`, `rsasha256`, and `rsasha512`.
    #[schema(example = "ecdsap256sha256")]
    pub algorithm: Option<String>,
    /// Denial-of-existence mode: `nsec3` (default, RFC 9276 parameters) or
    /// `nsec`, which leaves the zone's names walkable.
    #[schema(example = "nsec3")]
    pub denial: Option<String>,
    /// A KSK/ZSK pair instead of one CSK, so the ZSK rolls without touching
    /// the parent DS.
    #[serde(default)]
    #[schema(example = false)]
    pub split_keys: bool,
    /// Days a new signature stays valid (default 14).
    #[schema(example = 14)]
    pub signature_validity_days: Option<u32>,
    /// Re-sign when a signature has fewer than this many days left (default
    /// 5); must be below the validity.
    #[schema(example = 5)]
    pub signature_refresh_days: Option<u32>,
    /// Days an active ZSK may sign before the scheduler rolls it; 0 (the
    /// default) disables scheduled rolls.
    #[schema(example = 90)]
    pub zsk_lifetime_days: Option<u32>,
}

/// Request body for editing a DNSSEC policy's timing; an omitted field keeps
/// its value. Takes effect on the next signing pass or scheduler scan.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDnssecPolicyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 30)]
    pub signature_validity_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 7)]
    pub signature_refresh_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 90)]
    pub zsk_lifetime_days: Option<u32>,
}

/// API representation of a DNSSEC policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetDnssecPolicyResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: PolicyId,
    #[schema(example = "default")]
    pub name: String,
    /// Whether this is the built-in `default` policy, which cannot be deleted.
    #[schema(example = true)]
    pub builtin: bool,
    #[schema(example = "ecdsap256sha256")]
    pub algorithm: DnssecAlgorithm,
    pub denial: DnssecDenial,
    #[schema(example = false)]
    pub split_keys: bool,
    #[schema(example = 14, value_type = u32)]
    pub signature_validity_days: Days,
    #[schema(example = 5, value_type = u32)]
    pub signature_refresh_days: Days,
    /// 0 disables scheduled ZSK rollovers.
    #[schema(example = 0, value_type = u32)]
    pub zsk_lifetime_days: Days,
    pub created_at: DateTime<Utc>,
}

impl From<&DnssecPolicy> for GetDnssecPolicyResponse {
    /// Build a public response from a stored DNSSEC policy.
    fn from(policy: &DnssecPolicy) -> Self {
        GetDnssecPolicyResponse {
            id: policy.id,
            name: policy.name.clone(),
            builtin: policy.is_builtin(),
            algorithm: policy.algorithm,
            denial: policy.denial,
            split_keys: policy.split_keys,
            signature_validity_days: policy.signature_validity_days,
            signature_refresh_days: policy.signature_refresh_days,
            zsk_lifetime_days: policy.zsk_lifetime_days,
            created_at: policy.created_at,
        }
    }
}

/// A DNSSEC policy wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct DnssecPolicyResponse {
    pub dnssec_policy: GetDnssecPolicyResponse,
}
