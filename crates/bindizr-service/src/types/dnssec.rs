//! DNSSEC management payloads.

use bindizr_core::dns::dnssec::KeyTag;
use bindizr_core::dns::{Serial, Ttl};
use bindizr_core::model::dnssec_key::{
    DnssecAlgorithm, DnssecKey, DnssecKeyId, DnssecKeyRole, DnssecKeyState,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::types::dnssec_policy::DnssecPolicyResponse;

/// Whether a step that depends on the parent's DS asks the parent
/// nameservers, or takes the DS on the operator's word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsCheck {
    Probe,
    Skip,
}

impl DsCheck {
    /// Return the check a `skip_ds_check` flag asks for.
    pub fn from_skip_ds_check(skip_ds_check: bool) -> Self {
        if skip_ds_check {
            Self::Skip
        } else {
            Self::Probe
        }
    }

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Skip => "skip",
        }
    }
}

/// Whether a key promotion waits out the hold-down resolvers need to learn
/// the new key, or goes ahead at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Holddown {
    Wait,
    Skip,
}

impl Holddown {
    /// Return the wait a `skip_holddown` flag asks for.
    pub fn from_skip_holddown(skip_holddown: bool) -> Self {
        if skip_holddown {
            Self::Skip
        } else {
            Self::Wait
        }
    }

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wait => "wait",
            Self::Skip => "skip",
        }
    }
}

/// Request body for enabling DNSSEC on a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EnableDnssecRequest {
    /// Name of the DNSSEC policy to sign under; defaults to `default`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "default")]
    pub policy_name: Option<String>,
    /// The parent zone's nameservers as `host[:port]` entries, asked for the
    /// zone's DS by every later check.
    #[schema(example = json!(["a.gtld-servers.net", "b.gtld-servers.net"]))]
    pub parent_ns_addrs: Vec<String>,
}

/// Request body for changing a zone's signing settings; an omitted field
/// keeps its value.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDnssecSettingsRequest {
    /// Policy to move the signed zone to; it must share the zone's key
    /// layout. A new denial mode replaces the chain under one serial, and a
    /// new algorithm starts a rollover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "strict")]
    pub policy_name: Option<String>,
    /// The parent zone's nameservers as `host[:port]` entries; must name at
    /// least one server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = json!(["a.gtld-servers.net", "b.gtld-servers.net"]))]
    pub parent_ns_addrs: Option<Vec<String>>,
}

/// One of the zone's SEP keys against the parent's DS records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnssecDelegationKeyResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: DnssecKeyId,
    #[schema(example = 34217, value_type = u16)]
    pub key_tag: KeyTag,
    pub role: DnssecKeyRole,
    pub state: DnssecKeyState,
    /// Whether every parent server serves this key's DS (matched whole, not
    /// by key tag).
    #[schema(example = true)]
    pub ds_published: bool,
    /// Whether the parent serves a DS for this key tag only in digest types
    /// bindizr cannot compute, leaving `ds_published` undecided rather than
    /// answered.
    #[schema(example = false)]
    pub ds_digest_unsupported: bool,
    /// When a `published` key's hold-down ends.
    pub eligible_at: Option<DateTime<Utc>>,
}

/// Whether the parent serves a DS for the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DsState {
    Published,
    Hidden,
}

impl DsState {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Hidden => "hidden",
        }
    }
}

/// What the parent zone's servers answered when asked for the zone's DS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnssecDelegationResponse {
    /// The nameservers asked, from the zone's setting.
    pub parent_ns_addrs: Vec<String>,
    pub ds_state: DsState,
    /// Key tags of the DS records the parent serves.
    #[schema(value_type = Vec<u16>)]
    pub ds_key_tags: Vec<KeyTag>,
    /// The zone's SEP keys, each with whether the parent serves its DS.
    pub keys: Vec<DnssecDelegationKeyResponse>,
    /// TTL of the parent's DS records: how long caches may keep serving
    /// them once removed.
    #[schema(example = 86400, value_type = Option<Ttl>, inline)]
    pub ds_ttl: Option<Ttl>,
    pub checked_at: DateTime<Utc>,
}

/// Request body for starting a key rollover.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartDnssecRolloverRequest {
    /// Which key to roll: required for split-key zones (`ksk` or `zsk`),
    /// omitted for CSK zones.
    #[schema(example = "zsk")]
    pub role: Option<String>,
}

/// Public signing-key metadata; private material is excluded from HTTP responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnssecKeyResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: DnssecKeyId,
    pub role: DnssecKeyRole,
    /// Rollover lifecycle state.
    pub state: DnssecKeyState,
    pub state_changed_at: DateTime<Utc>,
    /// Next allowed transition: promotion for `published`, removal for
    /// `retired`; absent for `active`.
    pub eligible_at: Option<DateTime<Utc>>,
    #[schema(example = "ecdsap256sha256")]
    pub algorithm: DnssecAlgorithm,
    #[schema(example = 34217, value_type = u16)]
    pub key_tag: KeyTag,
    /// Apex DNSKEY RDATA: `<flags> 3 <alg> <public key>`; flags are 256 for
    /// a ZSK and 257 for a CSK or KSK.
    #[schema(
        example = "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
    )]
    pub dnskey: String,
    pub created_at: DateTime<Utc>,
}

impl From<&DnssecKey> for DnssecKeyResponse {
    /// Describe a stored key's public half and its place in the rollover.
    fn from(key: &DnssecKey) -> Self {
        Self {
            id: key.id,
            role: key.role,
            state: key.state,
            state_changed_at: key.state_changed_at,
            eligible_at: (key.state != DnssecKeyState::Active).then_some(key.eligible_at),
            algorithm: key.algorithm,
            key_tag: key.key_tag,
            dnskey: key.to_dnskey_presentation(),
            created_at: key.created_at,
        }
    }
}

/// A key's DS form for parent-zone registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnssecDsResponse {
    #[schema(example = 34217, value_type = u16)]
    pub key_tag: KeyTag,
    #[schema(example = 13)]
    pub algorithm: u8,
    /// DS digest type: always 2 (SHA-256), whatever the key algorithm.
    #[schema(example = 2)]
    pub digest_type: u8,
    #[schema(example = "4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383")]
    pub digest: String,
    /// Full presentation form: `<zone>. IN DS <tag> <alg> <digest_type> <digest>`.
    #[schema(
        example = "example.com. IN DS 34217 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383"
    )]
    pub presentation: String,
}

/// DNSSEC signing state of a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DnssecStatusResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(example = true)]
    pub enabled: bool,
    /// The policy the zone signs under; absent for an unsigned zone.
    pub policy: Option<DnssecPolicyResponse>,
    pub keys: Vec<DnssecKeyResponse>,
    /// DS forms of the keys, to be registered in the parent zone.
    pub ds_records: Vec<DnssecDsResponse>,
    /// Whether the RFC 8078 delete CDS/CDNSKEY pair is published, asking the
    /// parent to drop the zone's DS.
    #[serde(default)]
    #[schema(example = false)]
    pub withdrawing: bool,
    /// Configured parent nameservers; may also be set while the zone is unsigned.
    #[schema(example = json!(["a.gtld-servers.net", "b.gtld-servers.net"]))]
    pub parent_ns_addrs: Option<Vec<String>>,
    /// The parent's answer about the zone's DS; present only when this
    /// status comes from a parent check.
    pub delegation: Option<DnssecDelegationResponse>,
    /// Earliest stored signature expiration; the re-signer renews before it.
    pub earliest_signature_expires_at: Option<DateTime<Utc>>,
    /// Signatures the zone serves.
    #[schema(example = 42)]
    pub signatures: u64,
    /// Signatures already past their expiration; any at all mean resolvers
    /// are failing part of the zone.
    #[schema(example = 0)]
    pub expired_signatures: u64,
    /// When the re-signer next has work; absent for an unsigned zone.
    pub next_resign_at: Option<DateTime<Utc>>,
    #[schema(inline)]
    pub serial: Serial,
}

/// One key's BIND file contents. Served only over the daemon socket:
/// private keys never transit the HTTP API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecKeyMaterialResponse {
    pub role: DnssecKeyRole,
    /// IANA algorithm number.
    pub algorithm: u8,
    pub key_tag: KeyTag,
    /// `K*.key` contents: the DNSKEY record line.
    pub dnskey_record: String,
    /// `K*.private` contents.
    pub private_key: String,
}

/// Response body listing a zone's keys in BIND file form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDnssecKeysResponse {
    pub zone_name: String,
    pub keys: Vec<DnssecKeyMaterialResponse>,
}

/// One BIND key pair: `K*.key` contents (or the bare DNSKEY RDATA) and the
/// matching `K*.private` contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDnssecKeyPair {
    pub dnskey: String,
    pub private_key: String,
}

/// Request body importing a zone's complete key set; daemon-socket only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDnssecKeysRequest {
    /// One CSK pair, or a KSK pair and a ZSK pair under a split-key policy.
    /// The policy's layout decides the role of a SEP key.
    pub keys: Vec<ImportDnssecKeyPair>,
    /// Policy the zone signs under; defaults to `default`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `DsCheck` has one spelling across `as_str` and serde.
    #[test]
    fn ds_check_spells_itself_once() {
        for value in [DsCheck::Probe, DsCheck::Skip] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<DsCheck>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }

    /// Verify that `Holddown` has one spelling across `as_str` and serde.
    #[test]
    fn holddown_spells_itself_once() {
        for value in [Holddown::Wait, Holddown::Skip] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<Holddown>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }

    /// Verify that `DsState` has one spelling across `as_str` and serde.
    #[test]
    fn ds_state_spells_itself_once() {
        for value in [DsState::Published, DsState::Hidden] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<DsState>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }
}
