//! The grant payload API tokens and TSIG keys share.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request body for granting a credential record rights in a zone: an API
/// token's HTTP writes, or a TSIG key's updates and transfers.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateGrantRequest {
    /// Name of an existing zone.
    #[schema(example = "example.com")]
    pub zone_name: String,
    /// `*` (any name), `@` (apex), `*.sub` (subtree) or an exact relative name.
    /// Defaults to `*`.
    #[schema(example = "*.dyn")]
    pub record_name_pattern: Option<String>,
    /// `*` or a comma-separated list of record types. Defaults to `*`.
    #[schema(example = "A,AAAA,TXT")]
    pub record_types: Option<String>,
    /// Whether the grant carries write rights. A read-only grant still makes
    /// the zone visible to a token, narrowed the same way, and over a whole
    /// zone still lets a key transfer it. Defaults to true.
    #[serde(default = "default_can_write")]
    #[schema(example = true)]
    pub can_write: bool,
}

/// Enable write access when a new grant omits the permission flag.
fn default_can_write() -> bool {
    true
}
