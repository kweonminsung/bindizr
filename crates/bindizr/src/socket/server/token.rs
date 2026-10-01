use bindizr_core::model::token_grant::TokenGrantId;
use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    token::{self, grant},
    types::{
        CreateGrantRequest, CreateTokenRequest, CreatedTokenResponse, GetTokenGrantResponse,
        GetTokenResponse, MessageResponse, PageRequest, PaginatedResponse, TokenGrantResponse,
    },
    zone,
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
        data: CreatedTokenResponse {
            token: GetTokenResponse::from(&token),
            secret,
        },
    })
}

/// List the requested tokens.
pub(crate) async fn list_tokens(
    cx: &Context,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<GetTokenResponse>>, ServiceError> {
    let response = token::list(cx, &Caller::socket(), page).await?;
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

/// Create token grant from the control request.
pub(crate) async fn create_token_grant(
    cx: &Context,
    token_name: &str,
    request: &CreateGrantRequest,
) -> Result<DaemonResponse<TokenGrantResponse>, ServiceError> {
    let grant = grant::create(cx, &Caller::socket(), token_name, request).await?;
    Ok(DaemonResponse {
        message: "Token grant created successfully".to_string(),
        data: TokenGrantResponse {
            token_grant: GetTokenGrantResponse::from(&grant),
        },
    })
}

/// List the requested token grants for an API token.
pub(crate) async fn list_token_grants(
    cx: &Context,
    token_name: &str,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<GetTokenGrantResponse>>, ServiceError> {
    let response = grant::list_by_token(cx, &Caller::socket(), token_name, page).await?;
    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: response,
    })
}

/// List the requested token grants for a zone.
pub(crate) async fn list_zone_token_grants(
    cx: &Context,
    zone_name: &str,
    page: PageRequest,
) -> Result<DaemonResponse<PaginatedResponse<GetTokenGrantResponse>>, ServiceError> {
    let response = grant::list_by_zone(
        cx,
        &Caller::socket(),
        &zone::normalize_name(zone_name)?,
        page,
    )
    .await?;
    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: response,
    })
}

/// Delete the requested token grant.
pub(crate) async fn delete_token_grant(
    cx: &Context,
    id: TokenGrantId,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    grant::revoke_by_id(cx, &Caller::socket(), id).await?;
    let message = "Token grant revoked successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Revoke every grant the requested token holds in the requested zone.
pub(crate) async fn delete_token_grants_by_token_and_zone(
    cx: &Context,
    token_name: &str,
    zone_name: &str,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let revoked = grant::revoke_by_token_and_zone(
        cx,
        &Caller::socket(),
        token_name,
        &zone::normalize_name(zone_name)?,
    )
    .await?;
    let message = format!("{} token grant(s) revoked successfully", revoked);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
