//! Access log payloads.

use bindizr_core::model::access_log::{AccessLog, AccessResult, AccessSource};
use bindizr_core::model::change::ChangeActor;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Query parameters of the access log listing: which requests, their order,
/// and the page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AccessLogFilter {
    /// Only requests that arrived here: `api` or `nsupdate`.
    #[schema(example = "api")]
    pub source: Option<String>,
    /// Only requests that ended this way: `ok`, `denied`, or `failed`.
    #[schema(example = "denied")]
    pub result: Option<String>,
    /// Only requests made with the token or TSIG key of this name.
    #[schema(example = "external-dns")]
    pub caller_name: Option<String>,
    /// Only requests from this client IP address.
    #[schema(example = "192.0.2.10")]
    pub address: Option<String>,
    /// Only requests made at or after this time (RFC 3339).
    #[schema(example = "2026-10-01T00:00:00Z")]
    pub since: Option<DateTime<Utc>>,
    /// Only requests made before this time (RFC 3339).
    #[schema(example = "2026-11-01T00:00:00Z")]
    pub until: Option<DateTime<Utc>>,
    /// `requested_at` (the default), `source`, `target`, `status`, `result`,
    /// or `address`.
    #[schema(example = "requested_at")]
    pub sort: Option<String>,
    /// `desc` (the default) or `asc`.
    #[schema(example = "desc")]
    pub order: Option<String>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[schema(example = 50)]
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    #[schema(example = 0)]
    pub offset: Option<u64>,
}

/// One request a front end answered: what it asked, who asked, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AccessLogResponse {
    pub source: AccessSource,
    /// The connection's peer address; a proxy in front shows as itself.
    #[schema(example = "192.0.2.10")]
    pub address: String,
    /// The HTTP method, or `UPDATE` for an nsupdate.
    #[schema(example = "DELETE")]
    pub method: String,
    /// The request path without its query, or the zone an nsupdate named.
    #[schema(example = "/zones/example.com")]
    pub target: String,
    /// The HTTP status code, or the DNS RCODE.
    #[schema(example = "403")]
    pub status: String,
    pub result: AccessResult,
    /// The token or TSIG key the request authenticated with. Null when it
    /// presented none or what it presented did not verify, and when API
    /// authentication is off.
    pub caller: Option<ChangeActor>,
    /// The error the request was answered with; never a token or secret.
    #[schema(example = "role does not permit 'zone:delete' in zone 'example.com'")]
    pub error: Option<String>,
    pub requested_at: DateTime<Utc>,
}

impl From<&AccessLog> for AccessLogResponse {
    /// Build an access log response from a stored row.
    fn from(log: &AccessLog) -> Self {
        Self {
            source: log.source,
            address: log.client_addr.clone(),
            method: log.method.clone(),
            target: log.target.clone(),
            status: log.status.clone(),
            result: log.result,
            caller: log.caller.clone(),
            error: log.error.clone(),
            requested_at: log.requested_at,
        }
    }
}
