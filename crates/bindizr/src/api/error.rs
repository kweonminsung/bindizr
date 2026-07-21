use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bindizr_core::log_error;
use bindizr_service::error::{ErrorCode, ServiceError};

use crate::api::types::ErrorResponse;

/// Newtype over [`ServiceError`] so the service error can be converted into an
/// HTTP response (orphan rules forbid implementing `IntoResponse` directly).
#[derive(Debug)]
pub(crate) struct ApiError(pub ServiceError);

impl From<ServiceError> for ApiError {
    fn from(value: ServiceError) -> Self {
        ApiError(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(ErrorResponse::new(&self.0))).into_response()
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        log_error!("JSON Rejection: {:?}", rejection);

        let error = match rejection {
            JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_) => {
                ServiceError::new(
                    ErrorCode::InvalidJsonBody,
                    format!("Invalid JSON body: {}", rejection.body_text()),
                )
            }
            JsonRejection::MissingJsonContentType(_) => ServiceError::new(
                ErrorCode::UnsupportedMediaType,
                "Unsupported media type: expected 'Content-Type: application/json'",
            ),
            _ => ServiceError::internal("Failed to read request body"),
        };

        ApiError(error)
    }
}
