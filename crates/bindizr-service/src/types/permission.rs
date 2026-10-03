//! What the request's caller may do, computed from its role's grants.

use bindizr_core::model::role_grant::Action;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Actions held, and those held with no record name or type limit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, ToSchema)]
pub struct PermittedActionsResponse {
    /// The actions permitted.
    pub actions: Vec<Action>,
    /// Record actions with no name or type limit, as export, versions, diffs,
    /// import, and rollback need.
    pub whole_zone: Vec<Action>,
}

/// The caller's actions in one zone that differ from its every-zone actions.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ZonePermissionsResponse {
    #[schema(example = "example.com")]
    pub zone_name: String,
    pub actions: Vec<Action>,
    pub whole_zone: Vec<Action>,
}

/// What the caller may do across every zone, and where zone grants add to it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct PermissionsResponse {
    /// Applies to any zone not listed in `zones`, and to what no zone owns.
    pub all_zones: PermittedActionsResponse,
    pub zones: Vec<ZonePermissionsResponse>,
}
