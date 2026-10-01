//! Payloads not tied to one entity: messages, health, and errors.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ErrorCode, ServiceError};

/// Whether a previewable write goes through, or only reports what it
/// would do.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Run {
    Apply,
    DryRun,
}

impl Run {
    /// The run a `dry_run` flag asks for.
    pub fn from_dry_run(dry_run: bool) -> Self {
        if dry_run { Run::DryRun } else { Run::Apply }
    }

    /// Whether the run writes nothing.
    pub fn is_dry_run(self) -> bool {
        self == Run::DryRun
    }
}

/// Generic success message response.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Deleted successfully")]
    pub message: String,
}

/// Whether the API can serve requests: its database answered a probe.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

/// Health probe response.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct HealthResponse {
    pub status: HealthStatus,
}

/// Generic error response: a plain description plus a machine-readable code.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "zone with name 'example.com' not found")]
    pub error: String,
    /// Machine-readable failure classification.
    pub code: ErrorCode,
}

impl From<&ServiceError> for ErrorResponse {
    /// Build an error response from a service error's code and message.
    fn from(err: &ServiceError) -> Self {
        ErrorResponse {
            error: err.to_string(),
            code: err.code(),
        }
    }
}

impl Run {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::DryRun => "dry_run",
        }
    }
}

impl serde::Serialize for Run {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
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

impl serde::Serialize for HealthStatus {
    /// Serialize through the canonical spelling used by the wire contract.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the canonical spelling and round-trip of every Run variant.
    #[test]
    fn run_spells_itself_once() {
        for (value, expected) in [(Run::Apply, "apply"), (Run::DryRun, "dry_run")] {
            assert_eq!(value.as_str(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<Run>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
    }

    /// Verify the canonical spelling and round-trip of every HealthStatus variant.
    #[test]
    fn health_status_spells_itself_once() {
        for (value, expected) in [
            (HealthStatus::Healthy, "healthy"),
            (HealthStatus::Unhealthy, "unhealthy"),
        ] {
            assert_eq!(value.as_str(), expected);
            assert_eq!(
                serde_json::to_value(value).unwrap(),
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::from_value::<HealthStatus>(serde_json::json!(expected)).unwrap(),
                value
            );
        }
    }
}
