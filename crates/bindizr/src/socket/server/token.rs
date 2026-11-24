use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::types::{
    ApiTokenFilter, ApiTokenResponse, CreateApiTokenRequest, CreateApiTokenResponse,
    MessageResponse, PaginatedResponse,
};
use bindizr_service::{Context, token};

use crate::socket::types::DaemonResponse;

/// Create a token from the control request.
pub(crate) async fn create_token(
    cx: &Context,
    request: &CreateApiTokenRequest,
) -> Result<DaemonResponse<CreateApiTokenResponse>, ServiceError> {
    let (token, secret) = token::create(cx, &Caller::socket(), request).await?;
    Ok(DaemonResponse {
        message: "Token created successfully".to_string(),
        data: CreateApiTokenResponse { token, secret },
    })
}

/// List the requested tokens.
pub(crate) async fn list_tokens(
    cx: &Context,
    filter: &ApiTokenFilter,
) -> Result<DaemonResponse<PaginatedResponse<ApiTokenResponse>>, ServiceError> {
    let response = token::list(cx, &Caller::socket(), filter).await?;
    Ok(DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: response,
    })
}

/// Delete the requested token.
pub(crate) async fn delete_token(
    cx: &Context,
    name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let response = token::delete(cx, &Caller::socket(), name).await?;

    Ok(response.into())
}
