//! Activity log filters and payloads.

use bindizr_core::model::activity_log::{ActivityLog, ActivityOperation};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::PaginationResponse;

/// Select and page activity log rows, most recent first by default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ActivityLogFilter {
    /// The family of operations, such as `zone`, `record` or `secondary`.
    pub entity: Option<String>,
    /// A canonical operation name, such as `zone.create`.
    pub operation: Option<String>,
    /// An activity result, such as `changed`.
    pub result: Option<String>,
    /// The administrative target or zone name.
    pub name: Option<String>,
    /// The zone associated with the operation.
    pub zone_name: Option<String>,
    /// The record owner relative to its zone.
    pub record_name: Option<String>,
    /// The record's type mnemonic.
    pub record_type: Option<String>,
    /// At or after this time (RFC 3339).
    pub since: Option<DateTime<Utc>>,
    /// Before this time (RFC 3339).
    pub until: Option<DateTime<Utc>>,
    /// Order by `created_at` (default), `operation` or `target`.
    pub sort: Option<String>,
    /// `desc` (default) or `asc`.
    pub order: Option<String>,
    /// Items per page; the HTTP API defaults it, the daemon socket does not.
    #[param(minimum = 1, maximum = 1000)]
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// A page of activity log rows and the operations available as filters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ActivityLogResponse {
    pub items: Vec<ActivityLog>,
    pub pagination: PaginationResponse,
    /// Canonical operation names in catalog order, independent of the selected page.
    pub operations: Vec<ActivityOperation>,
}
