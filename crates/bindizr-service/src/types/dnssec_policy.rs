//! DNSSEC policy payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::dnssec_policy::DnssecPolicy;

/// Request body for creating a DNSSEC policy. The key layout, algorithm,
/// and denial mode are fixed once created. Omitted fields use the built-in
/// defaults, independent of edits to the policy named `default`.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
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
/// its value. Takes effect on the next signing pass or maintenance scan.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
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
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetDnssecPolicyResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "default")]
    pub name: String,
    #[schema(example = "ecdsap256sha256")]
    pub algorithm: String,
    /// `nsec` or `nsec3`.
    #[schema(example = "nsec3")]
    pub denial: String,
    #[schema(example = false)]
    pub split_keys: bool,
    #[schema(example = 14)]
    pub signature_validity_days: u32,
    #[schema(example = 5)]
    pub signature_refresh_days: u32,
    /// 0 disables scheduled ZSK rollovers.
    #[schema(example = 0)]
    pub zsk_lifetime_days: u32,
    pub created_at: DateTime<Utc>,
}

impl GetDnssecPolicyResponse {
    /// Build a public response from a stored DNSSEC policy.
    pub fn from_policy(policy: &DnssecPolicy) -> Self {
        GetDnssecPolicyResponse {
            id: policy.id,
            name: policy.name.clone(),
            algorithm: policy.algorithm.to_string(),
            denial: policy.denial.to_string(),
            split_keys: policy.split_keys,
            signature_validity_days: policy.signature_validity_days.max(0) as u32,
            signature_refresh_days: policy.signature_refresh_days.max(0) as u32,
            zsk_lifetime_days: policy.zsk_lifetime_days.max(0) as u32,
            created_at: policy.created_at,
        }
    }
}

/// A DNSSEC policy wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DnssecPolicyResponse {
    pub dnssec_policy: GetDnssecPolicyResponse,
}
