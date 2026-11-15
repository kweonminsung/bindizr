//! Transfer log payloads.

use bindizr_core::dns::Serial;
use bindizr_core::model::transfer::{
    TransferKind, TransferLogWithZone, TransferResult, TransferTransport,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Query parameters of the transfer log listing: which transfers, and the page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct TransferLogFilter {
    /// Only transfers answered to the addresses this secondary resolves to now.
    #[schema(example = "ns2")]
    pub secondary_name: Option<String>,
    /// Only transfers answered to this client IP address.
    #[schema(example = "10.0.0.14")]
    pub address: Option<String>,
    /// Only the transfers of this zone.
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    /// Only transfers that turned out this way: `ok`, `refused`, or `failed`.
    #[schema(example = "refused")]
    pub result: Option<String>,
    /// Only transfers answered at or after this time (RFC 3339).
    #[schema(example = "2026-10-01T00:00:00Z")]
    pub since: Option<DateTime<Utc>>,
    /// Only transfers answered before this time (RFC 3339).
    #[schema(example = "2026-11-01T00:00:00Z")]
    pub until: Option<DateTime<Utc>>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// One transfer Bindizr answered, refused, or failed for a client address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TransferLogResponse {
    /// The client address the transfer was served to.
    #[schema(example = "10.0.0.14")]
    pub address: String,
    #[schema(example = "example.com")]
    pub zone_name: String,
    pub kind: TransferKind,
    /// Answered, refused, or allowed and then broken off by a failure.
    pub result: TransferResult,
    /// Plain TCP or TLS (XoT).
    #[schema(example = "tcp")]
    pub transport: TransferTransport,
    /// Whether the answer was a delta; an IXFR the journal could not serve
    /// went out as the whole zone.
    #[schema(example = true)]
    pub incremental: bool,
    /// The serial the answer reached; absent when nothing was transferred.
    #[schema(inline)]
    pub serial: Option<Serial>,
    pub at: DateTime<Utc>,
    /// Why the transfer was refused or failed.
    pub error: Option<String>,
}

impl From<&TransferLogWithZone> for TransferLogResponse {
    /// Build the payload of one saved transfer.
    fn from(transfer: &TransferLogWithZone) -> Self {
        Self {
            address: transfer.client_addr.clone(),
            zone_name: transfer.zone_name.to_string(),
            kind: transfer.kind,
            result: transfer.result,
            transport: transfer.transport,
            incremental: transfer.incremental,
            serial: transfer.serial,
            at: transfer.served_at,
            error: transfer.error.clone(),
        }
    }
}
