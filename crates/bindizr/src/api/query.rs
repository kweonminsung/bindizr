//! Query parameters more than one endpoint reads.

use serde::Deserialize;

/// The preview switch every endpoint that offers one reads, so they all spell
/// it the same way and an absent one is the same as `false`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DryRunQuery {
    #[serde(default)]
    pub(crate) dry_run: bool,
}
