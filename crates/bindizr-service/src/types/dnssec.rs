//! DNSSEC management payloads.

use bindizr_core::{config::DnssecConfig, dns::query::DsAnswer};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::model::zone::Zone;

/// Request body for enabling DNSSEC on a zone.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
pub struct EnableDnssecRequest {
    /// Defaults to `ecdsap256sha256`; also accepts `ecdsap384sha384`, `ed25519`, `ed448`, `rsasha256`, and `rsasha512`.
    #[schema(example = "ecdsap256sha256")]
    pub algorithm: Option<String>,
    /// Denial-of-existence mode: `nsec` (default) or `nsec3` (RFC 9276
    /// parameters). Fixed at enable time.
    #[schema(example = "nsec3")]
    pub denial: Option<String>,
    /// Split KSK/ZSK keys instead of one CSK, so the ZSK rolls without
    /// touching the parent DS.
    #[serde(default)]
    #[schema(example = false)]
    pub split_keys: bool,
}

/// Request body for starting a key rollover.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
pub struct RolloverDnssecRequest {
    /// Which key to roll: required for split-key zones (`ksk` or `zsk`),
    /// omitted for CSK zones and algorithm rollovers.
    #[schema(example = "zsk")]
    pub role: Option<String>,
    /// Roll to this algorithm instead (RFC 6840, Section 5.11): replaces
    /// every key, double-signing the zone until the old keys leave.
    #[schema(example = "ed25519")]
    pub algorithm: Option<String>,
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
    /// When the DS poll first saw this key's DS at the parent; only pending
    /// SEP keys carry it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_seen_at: Option<DateTime<Utc>>,
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

impl DnssecDsInfo {
    /// Whether `answer`, a DS record served by a resolver, is this DS.
    pub fn matches(&self, answer: &DsAnswer) -> bool {
        i32::from(answer.key_tag) == self.key_tag
            && answer.algorithm == self.algorithm
            && answer.digest_type == self.digest_type
            && answer.digest == self.digest
    }
}

/// DNSSEC signing state of a zone.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct GetDnssecStatusResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    #[schema(example = true)]
    pub enabled: bool,
    /// Denial-of-existence mode: `nsec` or `nsec3`.
    #[schema(example = "nsec")]
    pub denial: String,
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
    pub timing: DnssecTimingInfo,
}

/// Per-zone signing timing: the values in effect after applying any zone
/// override to the global `[dnssec]` config, plus the stored overrides.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DnssecTimingInfo {
    #[schema(example = 30)]
    pub signature_validity_days: u32,
    #[schema(example = 7)]
    pub signature_refresh_days: u32,
    /// 0 disables scheduled ZSK rollovers.
    #[schema(example = 90)]
    pub zsk_lifetime_days: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validity_days_override: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_refresh_days_override: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zsk_lifetime_days_override: Option<i32>,
}

impl DnssecTimingInfo {
    pub fn from_zone(zone: &Zone, dnssec: &DnssecConfig) -> Self {
        DnssecTimingInfo {
            signature_validity_days: zone
                .signature_validity_days(dnssec.default_signature_validity_days),
            signature_refresh_days: zone
                .signature_refresh_days(dnssec.default_signature_refresh_days),
            zsk_lifetime_days: zone.zsk_lifetime_days(dnssec.default_zsk_lifetime_days),
            signature_validity_days_override: zone.dnssec_signature_validity_days,
            signature_refresh_days_override: zone.dnssec_signature_refresh_days,
            zsk_lifetime_days_override: zone.dnssec_zsk_lifetime_days,
        }
    }
}

/// Request body replacing a zone's timing overrides: an omitted field reverts
/// that knob to the global `[dnssec]` config.
#[derive(Serialize, Deserialize, Debug, Default, ToSchema)]
pub struct SetDnssecTimingRequest {
    /// Days a new signature stays valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 30)]
    pub signature_validity_days: Option<u32>,
    /// Re-sign when a signature has fewer than this many days left.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 7)]
    pub signature_refresh_days: Option<u32>,
    /// Days an active ZSK may sign before the scheduler rolls it; 0 disables
    /// scheduled rolls for this zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 90)]
    pub zsk_lifetime_days: Option<u32>,
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

/// Request body importing one BIND key pair; daemon-socket only.
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportDnssecKeyRequest {
    /// `K*.key` contents, or the bare DNSKEY RDATA.
    pub dnskey: String,
    /// `K*.private` contents.
    pub private_key: String,
    /// `csk`/`ksk`/`zsk`; required for a SEP key (flags 257), a 256 key
    /// imports as `zsk`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// One verification check's outcome.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct DnssecCheckInfo {
    #[schema(example = "signatures")]
    pub check: String,
    #[schema(example = true)]
    pub ok: bool,
    #[schema(example = "142 RRSIGs, earliest expiry 2026-09-12T00:00:00Z")]
    pub detail: String,
}

/// Result of verifying a zone's DNSSEC state.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct VerifyDnssecResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// Whether every check passed.
    #[schema(example = true)]
    pub ok: bool,
    pub checks: Vec<DnssecCheckInfo>,
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
