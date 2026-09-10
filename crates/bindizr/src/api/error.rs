use axum::{
    Json,
    extract::{FromRequestParts, rejection::JsonRejection},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use bindizr_core::log_error;
use bindizr_service::{
    error::{ErrorCode, ServiceError},
    types::ErrorResponse,
};
use serde::de::DeserializeOwned;

use crate::api::middleware::body_parser::MAX_UPLOAD_BODY_BYTES;

/// Newtype over [`ServiceError`] so the service error can be converted into an
/// HTTP response (orphan rules forbid implementing `IntoResponse` directly).
#[derive(Debug)]
pub(crate) struct ApiError(pub(crate) ServiceError);

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
            // A body over DefaultBodyLimit arrives as a BytesRejection; it is a
            // client size error, so keep axum's status instead of reporting 500.
            JsonRejection::BytesRejection(_)
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                ServiceError::new(
                    ErrorCode::PayloadTooLarge,
                    format!(
                        "Request body exceeds the {} MiB limit",
                        MAX_UPLOAD_BODY_BYTES / (1024 * 1024)
                    ),
                )
            }
            _ => ServiceError::internal("Failed to read request body"),
        };

        ApiError(error)
    }
}

/// `axum::extract::Query` whose rejection renders as [`ErrorResponse`].
pub(crate) struct Query<T>(pub(crate) T);

impl<T, S> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        axum::extract::Query::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(value)| Query(value))
            .map_err(|rejection| ApiError(ServiceError::invalid_input(rejection.body_text())))
    }
}

/// `axum::extract::Path` with the same treatment as [`Query`].
pub(crate) struct Path<T>(pub(crate) T);

impl<T, S> FromRequestParts<S> for Path<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        axum::extract::Path::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(value)| Path(value))
            .map_err(|rejection| ApiError(ServiceError::invalid_input(rejection.body_text())))
    }
}
