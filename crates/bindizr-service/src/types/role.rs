//! Role and role grant payloads.

use bindizr_core::{
    dns::name::ZoneName,
    model::{
        role::{Role, RoleId},
        role_grant::{Action, RoleGrant, RoleGrantId},
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request body for creating a role.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRoleRequest {
    /// Letters, digits, `.`, `_`, and `-`: one URL path segment.
    #[schema(example = "external-dns-prod")]
    pub name: String,
    /// At most 255 characters.
    #[schema(example = "ExternalDNS in the prod clusters")]
    pub description: Option<String>,
}

/// API representation of a role.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetRoleResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: RoleId,
    #[schema(example = "external-dns-prod")]
    pub name: String,
    pub description: Option<String>,
    /// Whether this is the built-in `admin` role, which can be neither changed nor deleted.
    #[schema(example = false)]
    pub builtin: bool,
    pub created_at: DateTime<Utc>,
}

impl From<&Role> for GetRoleResponse {
    /// Build a role response from the stored role.
    fn from(role: &Role) -> Self {
        GetRoleResponse {
            id: role.id,
            name: role.name.clone(),
            description: role.description.clone(),
            builtin: role.is_builtin(),
            created_at: role.created_at,
        }
    }
}

/// A single role wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RoleResponse {
    pub role: GetRoleResponse,
}

/// Request body for granting a role actions in one zone or every zone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRoleGrantRequest {
    /// Name of an existing zone; omit to cover every zone, including later ones.
    /// `zone:create`, `secondary:*` and `access:manage` need every zone.
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    /// The actions the grant permits, as `<resource>:<action>`.
    #[schema(example = json!(["record:read", "record:create", "record:update", "record:delete"]))]
    pub actions: Vec<String>,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative
    /// name. Constrains `record:*` actions only. Defaults to `*`.
    #[schema(example = "*.apps")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Constrains `record:*`
    /// actions only. Defaults to `*`.
    #[schema(example = "A,AAAA,CNAME,TXT")]
    pub record_types: Option<String>,
}

/// API representation of a role grant.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct GetRoleGrantResponse {
    #[schema(example = 1, value_type = i32)]
    pub id: RoleGrantId,
    #[schema(example = "external-dns-prod")]
    pub role_name: String,
    /// The zone the grant covers; `null` covers every zone.
    #[schema(example = "example.com")]
    pub zone_name: Option<String>,
    pub actions: Vec<Action>,
    #[schema(example = "*.apps")]
    pub record_name_pattern: String,
    #[schema(example = "A,AAAA,CNAME,TXT")]
    pub record_types: String,
    pub created_at: DateTime<Utc>,
}

impl GetRoleGrantResponse {
    /// Build a grant response with its role and zone names; no zone means every zone.
    pub(crate) fn from_grant(
        grant: &RoleGrant,
        role_name: &str,
        zone_name: Option<&ZoneName>,
    ) -> Self {
        GetRoleGrantResponse {
            id: grant.id,
            role_name: role_name.to_string(),
            zone_name: zone_name.map(|name| name.to_string()),
            actions: grant.actions.iter().collect(),
            record_name_pattern: grant.record_name_pattern.clone(),
            record_types: grant.record_types.clone(),
            created_at: grant.created_at,
        }
    }
}

/// A single role grant wrapped in a response envelope.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct RoleGrantResponse {
    pub role_grant: GetRoleGrantResponse,
}
