//! DNSSEC management payloads.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::GetDnssecPolicyResponse;

/// Request body for enabling DNSSEC on a zone.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
pub struct EnableDnssecRequest {
    /// Name of the DNSSEC policy to sign under; defaults to `default`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "default")]
    pub policy: Option<String>,
}

/// Request body for moving a signed zone to another DNSSEC policy.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SetZoneDnssecPolicyRequest {
    /// Name of an existing DNSSEC policy with the zone's denial mode and key
    /// layout; a different algorithm starts an algorithm rollover.
    #[schema(example = "strict")]
    pub policy: String,
}

/// Request body for starting a key rollover.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
pub struct RolloverDnssecRequest {
    /// Which key to roll: required for split-key zones (`ksk` or `zsk`),
    /// omitted for CSK zones.
    #[schema(example = "zsk")]
    pub role: Option<String>,
}

/// A signing key's public half; the private key never leaves the server.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DnssecKeyInfo {
    #[schema(example = 1)]
    pub id: i32,
    /// `csk`, `ksk`, or `zsk`.
    #[schema(example = "csk")]
    pub role: String,
    /// Rollover lifecycle state: `published`, `active`, or `retired`.
    #[schema(example = "active")]
    pub state: String,
    pub state_changed_at: DateTime<Utc>,
    /// Next allowed transition: promotion for `published`, removal for
    /// `retired`; absent for `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligible_at: Option<DateTime<Utc>>,
    #[schema(example = "ecdsap256sha256")]
    pub algorithm: String,
    #[schema(example = 34217)]
    pub key_tag: i32,
    /// Apex DNSKEY RDATA in presentation form: `257 3 <alg> <public key>`.
    #[schema(
        example = "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
    )]
    pub dnskey: String,
    pub created_at: DateTime<Utc>,
}

/// A key's DS form for parent-zone registration.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DnssecDsInfo {
    #[schema(example = 34217)]
    pub key_tag: i32,
    #[schema(example = 13)]
    pub algorithm: u8,
    /// DS digest type: 4 (SHA-384) for P-384 keys, otherwise 2 (SHA-256).
    #[schema(example = 2)]
    pub digest_type: u8,
    #[schema(example = "4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383")]
    pub digest: String,
    /// Full presentation form: `<zone>. IN DS <tag> <alg> 2 <digest>`.
    #[schema(
        example = "example.com. IN DS 34217 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383"
    )]
    pub presentation: String,
}

/// DNSSEC signing state of a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetDnssecStatusResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(example = true)]
    pub enabled: bool,
    /// The policy the zone signs under; absent for an unsigned zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<GetDnssecPolicyResponse>,
    pub keys: Vec<DnssecKeyInfo>,
    /// DS forms of the keys, to be registered in the parent zone.
    pub ds_records: Vec<DnssecDsInfo>,
    /// Whether the RFC 8078 delete CDS/CDNSKEY pair is published, asking the
    /// parent to drop the zone's DS.
    #[serde(default)]
    #[schema(example = false)]
    pub withdrawing: bool,
    /// Earliest stored signature expiration; the re-signer renews before it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_signature_expires_at: Option<DateTime<Utc>>,
    #[schema(example = 7)]
    pub serial: i32,
}

/// One key's BIND file contents. Served only over the daemon socket:
/// private keys never transit the HTTP API.
#[derive(Serialize, Deserialize, Debug)]
pub struct DnssecKeyMaterial {
    pub role: String,
    /// IANA algorithm number.
    pub algorithm: i32,
    pub key_tag: i32,
    /// `K*.key` contents: the DNSKEY record line.
    pub dnskey_record: String,
    /// `K*.private` contents.
    pub private_key: String,
}

/// Response body listing a zone's keys in BIND file form.
#[derive(Serialize, Deserialize, Debug)]
pub struct ExportDnssecKeysResponse {
    pub zone_name: String,
    pub keys: Vec<DnssecKeyMaterial>,
}

/// One BIND key pair: `K*.key` contents (or the bare DNSKEY RDATA) and the
/// matching `K*.private` contents.
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportDnssecKeyPair {
    pub dnskey: String,
    pub private_key: String,
}

/// Request body importing a zone's complete key set; daemon-socket only.
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportDnssecKeyRequest {
    /// One CSK pair, or a KSK pair and a ZSK pair under a split-key policy.
    /// The policy's layout decides the role of a SEP key.
    pub keys: Vec<ImportDnssecKeyPair>,
    /// Policy the zone signs under; defaults to `default`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// A zone's DNSSEC status wrapped in a response envelope.
#[derive(Serialize, Debug, ToSchema)]
pub struct DnssecStatusResponse {
    pub dnssec: GetDnssecStatusResponse,
}

/// The DS records of a zone's signing keys.
#[derive(Serialize, Debug, ToSchema)]
pub struct DnssecDsListResponse {
    pub ds_records: Vec<DnssecDsInfo>,
}
