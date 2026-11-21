//! Transfer log payloads.

use bindizr_core::dns::Serial;
use bindizr_core::model::transfer::{
    TransferKind, TransferLogWithZone, TransferResult, TransferTransport,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Query parameters of the transfer log listing: which transfers, their order,
/// and the page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct TransferLogFilter {
    /// Only transfers answered to the addresses this secondary resolves to now.
    pub secondary_name: Option<String>,
    /// Only transfers answered to this client IP address.
    pub address: Option<String>,
    /// Only the transfers of this zone.
    pub zone_name: Option<String>,
    /// Only transfers that turned out this way: `ok`, `refused`, or `failed`.
    pub result: Option<String>,
    /// Only transfers answered at or after this time (RFC 3339).
    pub since: Option<DateTime<Utc>>,
    /// Only transfers answered before this time (RFC 3339).
    pub until: Option<DateTime<Utc>>,
    /// `at` (the default), `address`, `zone_name`, `kind`, or `result`.
    pub sort: Option<String>,
    /// `desc` (the default) or `asc`.
    pub order: Option<String>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
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
        let log = &transfer.log;

        Self {
            address: log.client_addr.clone(),
            zone_name: transfer.zone_name.to_string(),
            kind: log.kind,
            result: log.result,
            transport: log.transport,
            incremental: log.incremental,
            serial: log.serial,
            at: log.served_at,
            error: log.error.clone(),
        }
    }
}
