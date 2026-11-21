use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bindizr_service::error::{ErrorCode, ServiceError};
use bindizr_service::types::ErrorResponse;
use thiserror::Error;

use crate::api::extract::{DEFAULT_BODY_BYTES, MAX_UPLOAD_BODY_BYTES};

/// Return the HTTP status each error code answers with. Every code is spelled out,
/// so a new one has to choose its status here.
pub(crate) fn http_status(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidInput
        | ErrorCode::InvalidZoneField
        | ErrorCode::InvalidRecordName
        | ErrorCode::InvalidRecordValue
        | ErrorCode::InvalidJsonBody => StatusCode::BAD_REQUEST,
        ErrorCode::Unauthorized | ErrorCode::InvalidToken => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ErrorCode::EndpointNotFound
        | ErrorCode::ZoneNotFound
        | ErrorCode::RecordNotFound
        | ErrorCode::TokenNotFound
        | ErrorCode::VersionNotFound
        | ErrorCode::SecondaryNotFound
        | ErrorCode::TsigKeyNotFound
        | ErrorCode::RoleNotFound
        | ErrorCode::RoleGrantNotFound
        | ErrorCode::DnssecPolicyNotFound => StatusCode::NOT_FOUND,
        ErrorCode::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::ZoneConflict
        | ErrorCode::RecordConflict
        | ErrorCode::TokenConflict
        | ErrorCode::SecondaryConflict
        | ErrorCode::TsigKeyConflict
        | ErrorCode::TsigKeyInUse
        | ErrorCode::RoleConflict
        | ErrorCode::RoleInUse
        | ErrorCode::DnssecAlreadyEnabled
        | ErrorCode::DnssecNotEnabled
        | ErrorCode::DnssecRolloverInProgress
        | ErrorCode::DnssecNoRolloverInProgress
        | ErrorCode::DnssecDsPublished
        | ErrorCode::DnssecDsNotPublished
        | ErrorCode::DnssecDsUnverified
        | ErrorCode::DnssecPolicyConflict
        | ErrorCode::DnssecPolicyInUse => StatusCode::CONFLICT,
        ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        // Server-side like Internal, but nameable for alerting.
        ErrorCode::DnssecSigningFailed | ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The message an error response carried, attached for the access log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ErrorMessage(pub(crate) String);

/// Newtype over [`ServiceError`] so the service error can be converted into an
/// HTTP response (orphan rules forbid implementing `IntoResponse` directly).
#[derive(Debug, Error)]
#[error(transparent)]
pub(crate) struct ApiError(pub(crate) ServiceError);

impl From<ServiceError> for ApiError {
    /// Wrap a service error for HTTP response conversion.
    fn from(error: ServiceError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    /// Convert a service error into its HTTP status and JSON error body.
    fn into_response(self) -> Response {
        // The one place a server fault leaves over HTTP, so its cause is logged here.
        if self.0.code().is_internal() {
            log::error!("HTTP request failed with a server fault: {:?}", self.0);
        }

        let status = http_status(self.0.code());
        let code = self.0.code();
        let body = ErrorResponse::from(&self.0);
        let message = ErrorMessage(body.error.clone());
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(message);

        // RFC 9110, Section 15.5.2 wants a challenge on every 401; RFC 6750, Section 3
        // spells it with a realm and, for a refused token, `error="invalid_token"`.
        if status == StatusCode::UNAUTHORIZED {
            let challenge = if code == ErrorCode::InvalidToken {
                "Bearer realm=\"bindizr\", error=\"invalid_token\""
            } else {
                "Bearer realm=\"bindizr\""
            };
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }

        response
    }
}

impl From<JsonRejection> for ApiError {
    /// Translate a JSON extraction failure into an API error.
    fn from(rejection: JsonRejection) -> Self {
        let error = match rejection {
            JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_) => {
                ServiceError::InvalidJsonBody {
                    message: format!("invalid JSON body: {}", rejection.body_text()),
                }
            }
            JsonRejection::MissingJsonContentType(_) => ServiceError::UnsupportedMediaType {
                message: "unsupported media type: expected 'Content-Type: application/json'"
                    .to_string(),
            },
            // A body over DefaultBodyLimit arrives as a BytesRejection; it is a
            // client size error, so keep axum's status instead of reporting 500.
            // The rejection does not say which limit the route carries.
            JsonRejection::BytesRejection(_)
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                // The routing table alone says which routes take the upload cap.
                ServiceError::PayloadTooLarge {
                    message: format!(
                        "request body exceeds the route's limit ({} MiB, or {} MiB for upload routes)",
                        DEFAULT_BODY_BYTES / (1024 * 1024),
                        MAX_UPLOAD_BODY_BYTES / (1024 * 1024)
                    ),
                }
            }
            // A body the client broke off or framed badly is the client's
            // mistake, which axum already classes as 4xx.
            JsonRejection::BytesRejection(_) if rejection.status().is_client_error() => {
                ServiceError::invalid_input(format!(
                    "failed to read request body: {}",
                    rejection.body_text()
                ))
            }
            _ => ServiceError::internal_with_source("failed to read request body", rejection),
        };

        Self(error)
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::Request;
    use bindizr_service::types::CreateRecordRequest;

    use super::*;

    /// Verify that an unknown body field is rejected, naming the field.
    #[tokio::test]
    async fn body_rejects_unknown_field_by_name() {
        let request = Request::builder()
            .method("POST")
            .uri("/records")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"www","type":"A","value":"192.0.2.1","zone_name":"example.com","tll":300}"#,
            ))
            .unwrap();

        let rejection = Json::<CreateRecordRequest>::from_request(request, &())
            .await
            .unwrap_err();
        let error = ApiError::from(rejection);

        assert_eq!(error.0.code(), ErrorCode::InvalidJsonBody);
        assert!(
            error.0.to_string().contains("unknown field `tll`"),
            "{}",
            error.0
        );
    }
}
