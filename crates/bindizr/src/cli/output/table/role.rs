use bindizr_core::model::role::RoleId;
use bindizr_core::model::role_grant::RoleGrantId;
use bindizr_service::types::{RoleGrantResponse, RoleResponse};
use tabled::Tabled;

use crate::cli::output::display;

#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct RoleRow {
    #[tabled(rename = "ID")]
    pub(crate) id: RoleId,
    #[tabled(rename = "NAME")]
    pub(crate) name: String,
    #[tabled(rename = "BUILTIN", display = "display::display_yes_no")]
    pub(crate) builtin: bool,
    #[tabled(rename = "GRANTS")]
    pub(crate) grant_count: u64,
    #[tabled(rename = "TOKENS")]
    pub(crate) token_count: u64,
    #[tabled(rename = "TSIG-KEYS")]
    pub(crate) tsig_key_count: u64,
    #[tabled(rename = "DESCRIPTION")]
    pub(crate) description: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&RoleResponse> for RoleRow {
    /// Build a CLI table row from the role response.
    fn from(role: &RoleResponse) -> Self {
        Self {
            id: role.id,
            name: role.name.clone(),
            builtin: role.builtin,
            grant_count: role.grant_count,
            token_count: role.token_count,
            tsig_key_count: role.tsig_key_count,
            description: display::display_option(&role.description),
            created_at: display::display_time(role.created_at),
        }
    }
}

/// ZONE reads `*` for a grant covering all zones.
#[derive(Debug, Clone, PartialEq, Eq, Tabled)]
pub(crate) struct RoleGrantRow {
    #[tabled(rename = "ID")]
    pub(crate) id: RoleGrantId,
    #[tabled(rename = "ROLE")]
    pub(crate) role_name: String,
    #[tabled(rename = "ZONE")]
    pub(crate) zone_name: String,
    #[tabled(rename = "ACTIONS")]
    pub(crate) actions: String,
    #[tabled(rename = "NAME-PATTERN")]
    pub(crate) record_name_pattern: String,
    #[tabled(rename = "RECORD-TYPES")]
    pub(crate) record_types: String,
    #[tabled(rename = "CREATED-AT")]
    pub(crate) created_at: String,
}

impl From<&RoleGrantResponse> for RoleGrantRow {
    /// Build a CLI table row from the role grant response.
    fn from(grant: &RoleGrantResponse) -> Self {
        Self {
            id: grant.id,
            role_name: grant.role_name.clone(),
            zone_name: grant.zone_name.clone().unwrap_or_else(|| "*".to_string()),
            actions: grant
                .actions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            record_name_pattern: grant.record_name_pattern.clone(),
            record_types: grant.record_types.clone(),
            created_at: display::display_time(grant.created_at),
        }
    }
}
