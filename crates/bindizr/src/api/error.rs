use axum::{
    Json,
    extract::{FromRequestParts, rejection::JsonRejection},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
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
    /// Wrap a service error for HTTP response conversion.
    fn from(value: ServiceError) -> Self {
        ApiError(value)
    }
}

impl IntoResponse for ApiError {
    /// Convert a service error into its HTTP status and JSON error body.
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(ErrorResponse::new(&self.0))).into_response()
    }
}

impl From<JsonRejection> for ApiError {
    /// Translate a JSON extraction failure into an API error.
    fn from(rejection: JsonRejection) -> Self {
        log::error!("JSON Rejection: {:?}", rejection);

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

    /// Parse URL query parameters and translate validation errors.
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

    /// Parse route parameters and translate validation errors.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        axum::extract::Path::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(value)| Path(value))
            .map_err(|rejection| ApiError(ServiceError::invalid_input(rejection.body_text())))
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, extract::FromRequest, http::Request};
    use bindizr_service::types::{CreateRecordRequest, DeleteRecordsFilter};

    use super::*;

    /// Verify that a misspelled query key is rejected, naming the key.
    #[tokio::test]
    async fn unknown_query_key_is_rejected_by_name() {
        // Dropping a key the filter does not declare would widen this delete
        // to every type at the name.
        let (mut parts, _) = Request::builder()
            .uri("/records?zone_name=example.com&name=www&record_type=A")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        let Err(error) = Query::<DeleteRecordsFilter>::from_request_parts(&mut parts, &()).await
        else {
            panic!("an unknown query key must be rejected");
        };
        assert_eq!(error.0.code, ErrorCode::InvalidInput);
        assert!(
            error.0.message.contains("unknown field `record_type`"),
            "{}",
            error.0.message
        );
    }

    /// Verify that the spelled-out filter still parses, keys and all.
    #[tokio::test]
    async fn known_query_keys_are_accepted() {
        let (mut parts, _) = Request::builder()
            .uri("/records?zone_name=example.com&name=www&type=A&dry_run=true")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        let Ok(Query(filter)) =
            Query::<DeleteRecordsFilter>::from_request_parts(&mut parts, &()).await
        else {
            panic!("the spelled-out filter must parse");
        };
        assert_eq!(filter.record_type.as_deref(), Some("A"));
        assert!(filter.dry_run);
    }

    /// Verify that an unknown body field is rejected, naming the field.
    #[tokio::test]
    async fn unknown_body_field_is_rejected_by_name() {
        let request = Request::builder()
            .method("POST")
            .uri("/records")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"www","type":"A","value":"192.0.2.1","zone_name":"example.com","tll":300}"#,
            ))
            .unwrap();

        let Err(rejection) = Json::<CreateRecordRequest>::from_request(request, &()).await else {
            panic!("an unknown body field must be rejected");
        };
        let error = ApiError::from(rejection);
        assert_eq!(error.0.code, ErrorCode::InvalidJsonBody);
        assert!(
            error.0.message.contains("unknown field `tll`"),
            "{}",
            error.0.message
        );
    }
}
