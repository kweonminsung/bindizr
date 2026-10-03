use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    token,
    types::{
        CreateTokenRequest, CreatedTokenResponse, GetTokenResponse, MessageResponse,
        PaginatedResponse, TokenFilter,
    },
};

use crate::socket::types::DaemonResponse;

/// Create token from the control request.
pub(crate) async fn create_token(
    cx: &Context,
    request: &CreateTokenRequest,
) -> Result<DaemonResponse<CreatedTokenResponse>, ServiceError> {
    let (token, secret) = token::create(cx, &Caller::socket(), request).await?;
    Ok(DaemonResponse {
        message: "Token created successfully".to_string(),
        data: CreatedTokenResponse { token, secret },
    })
}

/// List the requested tokens.
pub(crate) async fn list_tokens(
    cx: &Context,
    filter: &TokenFilter,
) -> Result<DaemonResponse<PaginatedResponse<GetTokenResponse>>, ServiceError> {
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
    token::delete(cx, &Caller::socket(), name).await?;
    let message = format!("Token '{}' deleted successfully", name);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
