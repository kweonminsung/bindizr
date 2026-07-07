use axum::{extract::rejection::JsonRejection, http::StatusCode, response::IntoResponse};
use axum_macros::FromRequest;
use bindizr_core::log_error;
use serde_json::json;

/// JSON body extractor that maps rejections to a JSON [`ApiError`] response.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub(crate) struct JsonBody<T>(pub T);

/// Error returned when JSON body extraction fails.
#[derive(Debug)]
pub(crate) struct ApiError {
    code: StatusCode,
    message: String,
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        let code = match rejection {
            JsonRejection::JsonDataError(_) => StatusCode::BAD_REQUEST,
            JsonRejection::JsonSyntaxError(_) => StatusCode::BAD_REQUEST,
            JsonRejection::MissingJsonContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        log_error!("JSON Rejection: {:?}", rejection);

        Self {
            code,
            message: "Invalid or malformed JSON body".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let payload = json!({
            "error": self.message,
        });

        (self.code, axum::Json(payload)).into_response()
    }
}
