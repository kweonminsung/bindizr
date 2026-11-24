//! Activity log retention.

use serde::{Deserialize, Serialize};

/// Retention for the rows served by `/logs/activity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityLogConfig {
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever.
    #[serde(default = "default_activity_log_max_days")]
    pub max_days: u32,
}

impl Default for ActivityLogConfig {
    /// Build the default activity log settings: a year.
    fn default() -> Self {
        Self {
            max_days: default_activity_log_max_days(),
        }
    }
}

/// Return the default days of activity log kept.
fn default_activity_log_max_days() -> u32 {
    365
}
