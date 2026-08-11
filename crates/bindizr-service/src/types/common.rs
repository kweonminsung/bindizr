//! Payloads not tied to one entity: messages, health, and errors.

use serde::Serialize;
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
#[derive(Serialize, Debug, ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "Zone with name 'example.com' not found")]
    pub error: String,
    #[schema(example = "ZONE_NOT_FOUND")]
    pub code: String,
}

impl ErrorResponse {
    pub fn new(err: &ServiceError) -> Self {
        ErrorResponse {
            error: err.message.clone(),
            code: err.code.as_str().to_string(),
        }
    }
}
