//! Zone version and incremental transfer retention.

use serde::{Deserialize, Serialize};

/// How long zone versions are kept, for diff and rollback, with the IXFR
/// journal behind incremental updates to secondaries; a pruned serial falls
/// back to AXFR. The scheduler pass prunes what is older.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryConfig {
    /// Days kept before the scheduler pass prunes older versions; `0` keeps
    /// them forever.
    #[serde(default = "default_history_max_days")]
    pub max_days: u32,
}

impl Default for HistoryConfig {
    /// Build the default zone history: a year.
    fn default() -> Self {
        Self {
            max_days: default_history_max_days(),
        }
    }
}

/// Return the default days of zone history kept.
fn default_history_max_days() -> u32 {
    365
}
