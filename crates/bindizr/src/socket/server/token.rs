use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    token::{TokenService, grant::TokenGrantService},
    types::{
        CreateTokenRequest, CreatedTokenResponse, GetTokenGrantResponse, GetTokenResponse,
        MessageResponse, PageFilter, TokenGrantResponse,
    },
};

use crate::{
    params::{IdParams, NameParams},
    socket::{
        server::{parse_params, to_response_data},
        types::{
            CreateTokenGrantParams, DaemonResponse, DeleteTokenGrantsByTokenAndZoneParams,
            ListGrantsParams,
        },
    },
};

/// Create token from the control request.
pub(crate) async fn create_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: CreateTokenRequest = parse_params(data)?;

    let (token, secret) = TokenService::create(
        &Caller::Global,
        &request.name,
        request.description.as_deref(),
        request.expires_in_days,
        request.global,
    )
    .await?;

    let response = DaemonResponse {
        message: "Token created successfully".to_string(),
        data: to_response_data(CreatedTokenResponse {
            token: GetTokenResponse::from_token(&token),
            secret,
        })?,
    };
    Ok(response)
}

/// List the requested tokens.
pub(crate) async fn list_tokens(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;

    let response = TokenService::list(&Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested token.
pub(crate) async fn delete_token(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    TokenService::delete(&Caller::Global, &params.name).await?;

    let message = format!("Token '{}' deleted successfully", params.name);
    let response = DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    };
    Ok(response)
}

/// Create token grant from the control request.
pub(crate) async fn create_token_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: CreateTokenGrantParams = parse_params(data)?;

    let grant = TokenGrantService::grant(
        &Caller::Global,
        &params.token_name,
        &params.request.zone_name,
        params.request.record_name_pattern.as_deref(),
        params.request.record_types.as_deref(),
        params.request.can_write,
    )
    .await?;

    Ok(DaemonResponse {
        message: "Token grant created successfully".to_string(),
        data: to_response_data(TokenGrantResponse {
            token_grant: GetTokenGrantResponse::from_grant(&grant),
        })?,
    })
}

/// List the requested token grants for an API token.
pub(crate) async fn list_token_grants(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListGrantsParams = parse_params(data)?;

    let response =
        TokenGrantService::list_by_token(&Caller::Global, &params.name, params.page).await?;

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// List the requested token grants for a zone.
pub(crate) async fn list_zone_token_grants(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListGrantsParams = parse_params(data)?;

    let response =
        TokenGrantService::list_by_zone(&Caller::Global, &params.name, params.page).await?;

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested token grant.
pub(crate) async fn delete_token_grant(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: IdParams = parse_params(data)?;

    TokenGrantService::revoke_by_id(&Caller::Global, params.id).await?;

    let message = "Token grant revoked successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Revoke every grant the requested token holds in the requested zone.
pub(crate) async fn delete_token_grants_by_token_and_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTokenGrantsByTokenAndZoneParams = parse_params(data)?;

    let revoked = TokenGrantService::revoke_by_token_and_zone(
        &Caller::Global,
        &params.token_name,
        &params.zone_name,
    )
    .await?;

    let message = format!("{} token grant(s) revoked successfully", revoked);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}
