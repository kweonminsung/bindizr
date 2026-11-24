//! Transfer log selection and retention.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::ParseConfigValueError;

/// The transfer log of what each client pulled, read under `/logs/transfer`:
/// which transfers are saved, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferLogConfig {
    #[serde(default)]
    pub save: SavedTransfers,
    /// Days kept before the scheduler pass prunes older entries; `0` keeps
    /// them forever. The newest transfer of each client and zone stays.
    #[serde(default = "default_transfer_log_max_days")]
    pub max_days: u32,
}

impl Default for TransferLogConfig {
    /// Build the default transfer log settings: every transfer, for 90 days.
    fn default() -> Self {
        Self {
            save: SavedTransfers::default(),
            max_days: default_transfer_log_max_days(),
        }
    }
}

/// Return the default days of transfer log kept.
fn default_transfer_log_max_days() -> u32 {
    90
}

/// Which transfers the transfer log saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SavedTransfers {
    /// Every transfer answered, refused, or failed.
    #[default]
    All,
    /// Refusals and failures alone.
    Unserved,
    /// No transfer: zone status and a secondary's summary then show none.
    None,
}

impl SavedTransfers {
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Unserved => "unserved",
            Self::None => "none",
        }
    }
}

impl fmt::Display for SavedTransfers {
    /// Write the setting in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SavedTransfers {
    type Err = ParseConfigValueError;

    /// Parse the setting from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "unserved" => Ok(Self::Unserved),
            "none" => Ok(Self::None),
            _ => Err(ParseConfigValueError {
                expected: "all, unserved, or none",
            }),
        }
    }
}
