//! Management audit log retention.

use serde::{Deserialize, Serialize};

/// The audit log of management changes, read under `/logs/audit`: how long
/// its entries are kept. Bindizr's own output is `[logging]`, not this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogConfig {
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever.
    #[serde(default = "default_audit_log_max_days")]
    pub max_days: u32,
}

impl Default for AuditLogConfig {
    /// Build the default audit log settings: a year.
    fn default() -> Self {
        Self {
            max_days: default_audit_log_max_days(),
        }
    }
}

/// Return the default days of audit log kept.
fn default_audit_log_max_days() -> u32 {
    365
}
