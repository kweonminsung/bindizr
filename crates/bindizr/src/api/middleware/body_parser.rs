use std::time::Instant;

use axum::{
    Json,
    extract::{FromRequest, Request, rejection::JsonRejection},
    http::StatusCode,
    response::IntoResponse,
};
use bindizr_core::{log_debug, log_error};
use serde::de::DeserializeOwned;
use serde_json::json;

/// JSON body extractor that maps rejections to a JSON [`ApiError`] response and
/// records deserialization time at debug level (`event=json_decode`), so the
/// JSON transport cost can be compared against the zone-file text path.
pub(crate) struct JsonBody<T>(pub T);

impl<T, S> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let start = Instant::now();
        let Json(value) = Json::<T>::from_request(req, state).await?;
        log_debug!(
            "event=json_decode ms={:.1}",
            start.elapsed().as_secs_f64() * 1000.0
        );
        Ok(Self(value))
    }
}

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
