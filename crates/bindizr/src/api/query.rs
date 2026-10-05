//! Query parameters more than one endpoint reads.

use serde::Deserialize;
use utoipa::IntoParams;

/// The preview switch every endpoint that offers one reads, so they all spell
/// it the same way and an absent one is the same as `false`.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub(crate) struct DryRunQuery {
    /// Report what the request would do without applying it.
    #[serde(default)]
    pub(crate) dry_run: bool,
}
