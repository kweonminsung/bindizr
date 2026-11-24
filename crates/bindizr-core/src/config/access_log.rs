//! Request access log selection and retention.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::ParseConfigValueError;

/// The access log of API requests and nsupdates, read under `/logs/access`:
/// which requests are saved, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    #[serde(default)]
    pub save: SavedRequests,
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever.
    #[serde(default = "default_access_log_max_days")]
    pub max_days: u32,
}

impl Default for AccessLogConfig {
    /// Build the default access log settings: every request, for 30 days.
    fn default() -> Self {
        Self {
            save: SavedRequests::default(),
            max_days: default_access_log_max_days(),
        }
    }
}

/// Return the default days of access log kept.
fn default_access_log_max_days() -> u32 {
    30
}

/// Which requests the access log saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedRequests {
    /// Every request answered, denied, or failed.
    #[default]
    All,
    /// Requests denied by authentication or authorization alone.
    Denied,
    /// No request: the access log stays empty.
    None,
}

impl SavedRequests {
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Denied => "denied",
            Self::None => "none",
        }
    }
}

impl fmt::Display for SavedRequests {
    /// Write the setting in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SavedRequests {
    type Err = ParseConfigValueError;

    /// Parse the setting from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "denied" => Ok(Self::Denied),
            "none" => Ok(Self::None),
            _ => Err(ParseConfigValueError {
                expected: "all, denied, or none",
            }),
        }
    }
}
