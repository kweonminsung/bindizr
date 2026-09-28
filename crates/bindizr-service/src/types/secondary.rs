//! Secondary server payloads.

use std::collections::HashMap;

use bindizr_core::{
    dns::Serial,
    model::{
        secondary::SecondaryId,
        transfer::{TransferKind, TransferResult, TransferWithZone},
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{model::secondary::Secondary, types::SecondaryStatusResponse};

/// Request body for registering a secondary.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSecondaryRequest {
    /// A plain identifier, since it travels in URL paths.
    #[schema(example = "ns2")]
    pub name: String,
    /// `host[:port]`, port 53 when left out; a hostname is resolved when used.
    #[schema(example = "ns2.example.net:53")]
    pub address: String,
    /// TSIG key to sign NOTIFY to this server with; omitted sends it unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "notify-key")]
    pub notify_key_name: Option<String>,
}

/// Request body for changing a secondary; an omitted field keeps its value.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSecondaryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "192.0.2.7:53")]
    pub address: Option<String>,
    /// `false` stops NOTIFY, unsigned transfers, and probes without
    /// forgetting the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = true)]
    pub enabled: Option<bool>,
    /// TSIG key to sign NOTIFY with; empty sends it unsigned again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(example = "notify-key")]
    pub notify_key_name: Option<String>,
}

/// API representation of a secondary.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetSecondaryResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: SecondaryId,
    #[schema(example = "ns2")]
    pub name: String,
    #[schema(example = "ns2.example.net:53")]
    pub address: String,
    #[schema(example = true)]
    pub enabled: bool,
    /// The TSIG key NOTIFY to this server is signed with, if any.
    #[schema(example = "notify-key")]
    pub notify_key_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl GetSecondaryResponse {
    /// Build the API representation from a stored secondary and its NOTIFY
    /// key's name.
    pub fn from_secondary(secondary: &Secondary, notify_key_name: Option<&str>) -> Self {
        GetSecondaryResponse {
            id: secondary.id,
            name: secondary.name.clone(),
            address: secondary.address.clone(),
            enabled: secondary.enabled,
            notify_key_name: notify_key_name.map(str::to_string),
            created_at: secondary.created_at,
        }
    }
}

/// A secondary wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SecondaryResponse {
    pub secondary: GetSecondaryResponse,
}

/// One NOTIFY sent to a resolved address during a check; `error` is null
/// when the server accepted it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct NotifyCheckResponse {
    #[schema(example = "10.0.0.14:53")]
    pub address: String,
    pub error: Option<String>,
}

/// What a secondary answered when checked: where its address resolves, the
/// catalog zone serial it serves against Bindizr's, and whether it accepted
/// a NOTIFY.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SecondaryCheckResponse {
    pub secondary: GetSecondaryResponse,
    /// Socket addresses the registered `host[:port]` resolves to now.
    #[schema(example = json!(["10.0.0.14:53"]))]
    pub addresses: Vec<String>,
    pub resolve_error: Option<String>,
    /// The catalog zone the secondary was asked for.
    #[schema(example = "catalog.bindizr")]
    pub catalog_zone_name: String,
    /// The serial Bindizr's own listener serves the catalog zone at; absent
    /// with `listener_error`, and `catalog` is then `reachable` at best.
    #[schema(example = 42, value_type = Option<u32>)]
    pub catalog_serial: Option<Serial>,
    pub listener_error: Option<String>,
    /// The secondary's catalog probe, classified against `catalog_serial`.
    pub catalog: SecondaryStatusResponse,
    /// The NOTIFY sent for the catalog zone, one per resolved address.
    pub notifies: Vec<NotifyCheckResponse>,
    /// How Bindizr served the secondary's transfers.
    pub transfers: TransferSummary,
}

/// One transfer Bindizr answered, refused, or failed for a secondary's address.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct TransferResponse {
    /// The client address the transfer was served to.
    #[schema(example = "10.0.0.14")]
    pub address: String,
    #[schema(example = "example.com")]
    pub zone_name: String,
    pub kind: TransferKind,
    /// Answered, refused, or allowed and then broken off by a failure.
    pub result: TransferResult,
    /// Whether the answer was a delta; an IXFR the journal could not serve
    /// went out as the whole zone.
    #[schema(example = true)]
    pub incremental: bool,
    /// The serial the answer reached; absent when nothing was transferred.
    #[schema(example = 42, value_type = Option<u32>)]
    pub serial: Option<Serial>,
    pub at: DateTime<Utc>,
    /// Why the transfer was refused or failed.
    pub error: Option<String>,
}

impl From<&TransferWithZone> for TransferResponse {
    /// Build the payload of one saved transfer.
    fn from(transfer: &TransferWithZone) -> Self {
        TransferResponse {
            address: transfer.client_addr.clone(),
            zone_name: transfer.zone_name.to_string(),
            kind: transfer.kind,
            result: transfer.result,
            incremental: transfer.incremental,
            serial: transfer.serial,
            at: transfer.served_at,
            error: transfer.error.clone(),
        }
    }
}

/// How the zones a secondary asked for were last served, counted by zone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct TransferSummary {
    #[schema(example = 12)]
    pub zones: u64,
    #[schema(example = 1)]
    pub axfr: u64,
    /// IXFR asked for and the whole zone sent.
    #[schema(example = 0)]
    pub ixfr_full: u64,
    #[schema(example = 11)]
    pub ixfr_delta: u64,
    #[schema(example = 0)]
    pub refused: u64,
    /// Allowed, then broken off by a failure.
    #[schema(example = 0)]
    pub failed: u64,
}

impl From<&[TransferWithZone]> for TransferSummary {
    /// Count each zone by its latest transfer among `transfers`.
    fn from(transfers: &[TransferWithZone]) -> Self {
        let mut latest: HashMap<&str, &TransferWithZone> = HashMap::new();
        for transfer in transfers {
            let entry = latest
                .entry(transfer.zone_name.as_str())
                .or_insert(transfer);
            if transfer.served_at > entry.served_at {
                *entry = transfer;
            }
        }
        let mut summary = TransferSummary {
            zones: latest.len() as u64,
            axfr: 0,
            ixfr_full: 0,
            ixfr_delta: 0,
            refused: 0,
            failed: 0,
        };
        for transfer in latest.values() {
            match (transfer.result, transfer.kind, transfer.incremental) {
                (TransferResult::Refused, _, _) => summary.refused += 1,
                (TransferResult::Failed, _, _) => summary.failed += 1,
                (TransferResult::Ok, TransferKind::Axfr, _) => summary.axfr += 1,
                (TransferResult::Ok, TransferKind::Ixfr, true) => summary.ixfr_delta += 1,
                (TransferResult::Ok, TransferKind::Ixfr, false) => summary.ixfr_full += 1,
            }
        }
        summary
    }
}

/// The transfers Bindizr served one secondary.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SecondaryTransfersResponse {
    #[schema(example = "ns2")]
    pub secondary_name: String,
    #[schema(example = "ns2.example.net:53")]
    pub address: String,
    pub summary: TransferSummary,
    /// Newest first, at most the requested `limit`.
    pub transfers: Vec<TransferResponse>,
}

/// One secondary's transfer summary, as `doctor` reports it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SecondaryTransferSummary {
    #[schema(example = "ns2")]
    pub secondary_name: String,
    #[schema(example = "ns2.example.net:53")]
    pub address: String,
    pub summary: TransferSummary,
}

/// Query parameters of a secondary's transfer listing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct GetSecondaryTransfersFilter {
    /// At most this many transfers, newest first; 1000 when omitted.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    /// Only the transfers of this zone.
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
}

impl SecondaryCheckResponse {
    /// Whether every part of the check passed: resolved, in sync, and every
    /// NOTIFY accepted. The transfer summary is information, not a verdict.
    pub fn is_healthy(&self) -> bool {
        self.resolve_error.is_none()
            && self.catalog.is_in_sync()
            && self.notifies.iter().all(|notify| notify.error.is_none())
    }
}
