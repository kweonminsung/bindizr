use axum::{
    Json,
    extract::{FromRequest, Request},
};
use serde::de::DeserializeOwned;

use crate::api::error::ApiError;

/// Body cap for whole-zone-file / bulk uploads (import, bulk create) — above
/// axum's 2 MiB default, but bounded to limit per-request memory.
pub(crate) const MAX_UPLOAD_BODY_BYTES: usize = 32 * 1024 * 1024;

/// JSON body extractor whose rejections render as a JSON [`ApiError`] response
/// rather than axum's plain-text default.
pub(crate) struct JsonBody<T>(pub(crate) T);

impl<T, S> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// Parse a JSON request body into the expected input type.
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await?;
        Ok(Self(value))
    }
}
