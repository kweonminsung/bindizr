//! Payloads not tied to one entity: messages, health, and errors.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ServiceError;

/// Whether a previewable write goes through, or only reports what it
/// would do.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, ToSchema)]
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
    #[schema(example = "Zone with name 'example.com' not found")]
    pub error: String,
    /// One of `INVALID_INPUT`, `INVALID_ZONE_FIELD`, `INVALID_RECORD_NAME`,
    /// `INVALID_RECORD_VALUE`, `INVALID_JSON_BODY`, `UNAUTHORIZED`,
    /// `INVALID_TOKEN`, `FORBIDDEN`, `ENDPOINT_NOT_FOUND`,
    /// `METHOD_NOT_ALLOWED`, `ZONE_NOT_FOUND`, `RECORD_NOT_FOUND`,
    /// `TOKEN_NOT_FOUND`, `VERSION_NOT_FOUND`, `SECONDARY_NOT_FOUND`,
    /// `TSIG_KEY_NOT_FOUND`,
    /// `TSIG_GRANT_NOT_FOUND`, `TOKEN_GRANT_NOT_FOUND`,
    /// `DNSSEC_POLICY_NOT_FOUND`, `ZONE_CONFLICT`, `RECORD_CONFLICT`,
    /// `TOKEN_CONFLICT`, `SECONDARY_CONFLICT`, `TSIG_KEY_CONFLICT`,
    /// `TSIG_KEY_IN_USE`,
    /// `DNSSEC_POLICY_CONFLICT`, `DNSSEC_POLICY_IN_USE`,
    /// `DNSSEC_ALREADY_ENABLED`, `DNSSEC_NOT_ENABLED`,
    /// `DNSSEC_ROLLOVER_IN_PROGRESS`, `DNSSEC_NO_ROLLOVER_IN_PROGRESS`,
    /// `DNSSEC_DS_PUBLISHED`, `DNSSEC_DS_NOT_PUBLISHED`,
    /// `DNSSEC_DS_UNVERIFIED`, `PAYLOAD_TOO_LARGE`,
    /// `UNSUPPORTED_MEDIA_TYPE`, `DNSSEC_SIGNING_FAILED`, `INTERNAL`.
    #[schema(example = "ZONE_NOT_FOUND", pattern = "^[A-Z_]+$")]
    pub code: String,
}

impl From<&ServiceError> for ErrorResponse {
    /// Build an error response from a service error's code and message.
    fn from(err: &ServiceError) -> Self {
        ErrorResponse {
            error: err.to_string(),
            code: err.code().as_str().to_string(),
        }
    }
}
