//! The path parameters that address one entity, shared by the HTTP API's
//! handlers.

use bindizr_core::model::record::RecordId;
use bindizr_core::model::role_grant::RoleGrantId;
use serde::Deserialize;

/// The name of the zone, secondary, token, key, or policy addressed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameParams {
    pub(crate) name: String,
}

/// The id of the record addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdParams {
    pub(crate) id: RecordId,
}

/// A grant, by the name of its role and its own id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NameIdParams {
    pub(crate) name: String,
    pub(crate) id: RoleGrantId,
}
