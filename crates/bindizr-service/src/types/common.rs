//! Payloads not tied to one entity: messages, health, and errors.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ErrorCode, ServiceError};

/// Whether a previewable write goes through, or only reports what it
/// would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Run {
    Apply,
    DryRun,
}

impl Run {
    /// Return the run a `dry_run` flag asks for.
    pub fn from_dry_run(dry_run: bool) -> Self {
        if dry_run {
            Self::DryRun
        } else {
            Self::Apply
        }
    }

    /// Return whether the run writes nothing.
    pub fn is_dry_run(self) -> bool {
        self == Self::DryRun
    }

    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::DryRun => "dry_run",
        }
    }
}

/// Generic success message response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Deleted successfully")]
    pub message: String,
}

/// Whether the API can serve requests: its database answered a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

impl HealthStatus {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Health probe response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: HealthStatus,
}

/// Generic error response: a plain description plus a machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "zone with name 'example.com' not found")]
    pub error: String,
    /// Machine-readable failure classification.
    pub code: ErrorCode,
}

impl From<&ServiceError> for ErrorResponse {
    /// Build an error response from a service error's code and message.
    fn from(error: &ServiceError) -> Self {
        Self {
            error: error.to_string(),
            code: error.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `Run` has one spelling across `as_str` and serde.
    #[test]
    fn run_spells_itself_once() {
        for value in [Run::Apply, Run::DryRun] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<Run>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }

    /// Verify that `HealthStatus` has one spelling across `as_str` and serde.
    #[test]
    fn health_status_spells_itself_once() {
        for value in [HealthStatus::Healthy, HealthStatus::Unhealthy] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<HealthStatus>(json!(value.as_str())).unwrap(),
                value
            );
        }
    }
}
