use std::time::Instant;

use axum::{
    Json,
    extract::{FromRequest, Request},
};
use bindizr_core::log_debug;
use serde::de::DeserializeOwned;

use crate::api::error::ApiError;

/// Body cap for whole-zone-file / bulk uploads (import, bulk create) — above
/// axum's 2 MiB default, but bounded to limit per-request memory.
pub(crate) const MAX_UPLOAD_BODY_BYTES: usize = 32 * 1024 * 1024;

/// JSON body extractor that maps rejections to a JSON [`ApiError`] response and
/// records deserialization time at debug level (`event=json_decode`), so the
/// JSON transport cost can be compared against the zone-file text path.
pub(crate) struct JsonBody<T>(pub(crate) T);

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
