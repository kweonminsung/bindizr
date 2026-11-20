//! Request extractors whose rejections render as a JSON [`ApiError`], and
//! the body limits the routes apply.

use axum::Json;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use bindizr_core::model::api_token::ApiToken;
use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use serde::de::DeserializeOwned;

use crate::api::error::ApiError;

/// Body cap for every route that does not raise it: axum's 2 MiB default,
/// set explicitly so the 413 message can name it.
pub(crate) const DEFAULT_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Body cap for whole-zone-file / bulk uploads (import, bulk create) — above
/// the default, but bounded to limit per-request memory.
pub(crate) const MAX_UPLOAD_BODY_BYTES: usize = 32 * 1024 * 1024;

/// JSON body extractor whose rejections render as a JSON [`ApiError`] response
/// rather than axum's plain-text default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JsonBody<T>(pub(crate) T);

impl<T, S> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// Parse a JSON request body into the expected input type.
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(request, state).await?;
        Ok(Self(value))
    }
}

/// `axum::extract::Query` whose rejection renders as [`ApiError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            .map(|axum::extract::Query(value)| Self(value))
            .map_err(|rejection| ApiError(ServiceError::invalid_input(rejection.body_text())))
    }
}

/// `axum::extract::Path` with the same treatment as [`Query`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            .map(|axum::extract::Path(value)| Self(value))
            .map_err(|rejection| ApiError(ServiceError::invalid_input(rejection.body_text())))
    }
}

/// The caller attached by the auth middleware, or by the router's
/// `Caller::unauthenticated_api()` layer when authentication is disabled. A request without
/// one reached a handler outside both layers, so extraction fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestCaller(pub(crate) Caller);

impl<S> FromRequestParts<S> for RequestCaller
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// Extract the authorized caller from request extensions.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<Caller>()
            .cloned()
            .map(RequestCaller)
            .ok_or_else(|| ApiError(ServiceError::unauthorized("request has no caller identity")))
    }
}

/// The token a request authenticated with, attached by the auth middleware;
/// absent when authentication is disabled, so a self-reading route answers 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedToken(pub(crate) ApiToken);

impl<S> FromRequestParts<S> for AuthenticatedToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// Extract the authenticated API token from request extensions.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        parts.extensions.get::<Self>().cloned().ok_or_else(|| {
            ApiError(ServiceError::TokenNotFound(
                "the request presents no API token: authentication is disabled".to_string(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use bindizr_service::error::ErrorCode;
    use bindizr_service::types::DeleteRecordsRequest;

    use super::*;

    /// Verify that a misspelled query key is rejected, naming the key.
    #[tokio::test]
    async fn query_rejects_unknown_key_by_name() {
        // Dropping a key the filter does not declare would widen this delete
        // to every type at the name.
        let (mut parts, _) = Request::builder()
            .uri("/records?zone_name=example.com&name=www&record_type=A")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        let error = Query::<DeleteRecordsRequest>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();

        assert_eq!(error.0.code(), ErrorCode::InvalidInput);
        assert!(
            error.0.to_string().contains("unknown field `record_type`"),
            "{}",
            error.0
        );
    }

    /// Verify that the spelled-out filter still parses, keys and all.
    #[tokio::test]
    async fn query_accepts_known_keys() {
        let (mut parts, _) = Request::builder()
            .uri("/records?zone_name=example.com&name=www&type=A&dry_run=true")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        let Query(request) = Query::<DeleteRecordsRequest>::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert_eq!(request.record_type.as_deref(), Some("A"));
        assert!(request.dry_run);
    }
}
