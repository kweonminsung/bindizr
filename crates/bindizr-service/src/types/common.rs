//! Payloads not tied to one entity: messages, health, and errors.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ServiceError;

/// Generic success message response.
#[derive(Serialize, Debug, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Deleted successfully")]
    pub message: String,
}

/// Health probe response.
#[derive(Serialize, Debug, ToSchema)]
pub struct HealthResponse {
    #[schema(example = "healthy")]
    pub status: String,
}

/// Generic error response: a plain description plus a machine-readable code.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
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

impl ErrorResponse {
    /// Build an error response from a service error's code and message.
    pub fn new(err: &ServiceError) -> Self {
        ErrorResponse {
            error: err.message.clone(),
            code: err.code.as_str().to_string(),
        }
    }
}
