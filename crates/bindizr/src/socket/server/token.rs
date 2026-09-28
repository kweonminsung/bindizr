use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    token::{self, grant},
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
pub(crate) async fn create_token(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: CreateTokenRequest = parse_params(data)?;

    let (token, secret) = token::create(
        cx,
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
pub(crate) async fn list_tokens(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let page: PageFilter = parse_params(data)?;

    let response = token::list(cx, &Caller::Global, page).await?;

    Ok(DaemonResponse {
        message: "Tokens retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested token.
pub(crate) async fn delete_token(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NameParams = parse_params(data)?;

    token::delete(cx, &Caller::Global, &params.name).await?;

    let message = format!("Token '{}' deleted successfully", params.name);
    let response = DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    };
    Ok(response)
}

/// Create token grant from the control request.
pub(crate) async fn create_token_grant(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: CreateTokenGrantParams = parse_params(data)?;

    let grant = grant::create(
        cx,
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
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListGrantsParams = parse_params(data)?;

    let response = grant::list_by_token(cx, &Caller::Global, &params.name, params.page).await?;

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// List the requested token grants for a zone.
pub(crate) async fn list_zone_token_grants(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: ListGrantsParams = parse_params(data)?;

    let response = grant::list_by_zone(cx, &Caller::Global, &params.name, params.page).await?;

    Ok(DaemonResponse {
        message: "Token grants retrieved successfully".to_string(),
        data: to_response_data(response)?,
    })
}

/// Delete the requested token grant.
pub(crate) async fn delete_token_grant(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: IdParams = parse_params(data)?;

    grant::revoke_by_id(cx, &Caller::Global, params.id).await?;

    let message = "Token grant revoked successfully".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Revoke every grant the requested token holds in the requested zone.
pub(crate) async fn delete_token_grants_by_token_and_zone(
    cx: &Context,
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: DeleteTokenGrantsByTokenAndZoneParams = parse_params(data)?;

    let revoked =
        grant::revoke_by_token_and_zone(cx, &Caller::Global, &params.token_name, &params.zone_name)
            .await?;

    let message = format!("{} token grant(s) revoked successfully", revoked);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}
