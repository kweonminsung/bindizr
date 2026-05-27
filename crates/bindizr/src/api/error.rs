use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

/// API-specific error type that can be converted to HTTP responses
#[derive(Debug, Error)]
pub(crate) enum ApiError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_message(&self) -> String {
        self.to_string()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(json!({
            "error": self.error_message()
        }));
        (status, body).into_response()
    }
}

impl From<crate::service::error::ServiceError> for ApiError {
    fn from(value: crate::service::error::ServiceError) -> Self {
        match value {
            crate::service::error::ServiceError::BadRequest(msg) => ApiError::BadRequest(msg),
            crate::service::error::ServiceError::NotFound(msg) => ApiError::NotFound(msg),
            crate::service::error::ServiceError::Unauthorized(msg) => ApiError::Unauthorized(msg),
            crate::service::error::ServiceError::Internal(msg) => {
                ApiError::InternalServerError(msg)
            }
        }
    }
}
